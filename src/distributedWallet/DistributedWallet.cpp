// === Includes ===
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <netinet/in.h>
#include <unistd.h>
#include <csignal>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <sqlite3.h>
#include "DistributedWallet.h"

// === Globals ===
EC_GROUP* ec_group = nullptr;
BIGNUM* ec_order = nullptr;
BN_CTX* bn_context = nullptr;

static std::unordered_map<std::string, int> publicKeyToIndex;
static int participantCounter = 0;
std::map<int, int> serverSockets;

std::mutex publicKeyMutex;
std::mutex socketMapMutex;

volatile bool running = true;


// === Signal Handling ===
void signalHandler(int signum) {
    running = false;
    std::cout << "\nStopping server..." << std::endl;

    std::lock_guard<std::mutex> lock(socketMapMutex);
    for (auto& [port, sockfd] : serverSockets) {
        shutdown(sockfd, SHUT_RDWR);
    }
}

// === Utilities ===
/**
 * @brief Creates multiple SQLite databases for storing key shares.
 *
 * @param num_participants Number of participant databases to create.
 */
void initializeKeyShareDatabases(int num_participants) {
    for (int i = 0; i < num_participants; ++i) {
        std::string db_filename = "storage_" + std::to_string(i + 1) + ".db";
        sqlite3* db_connection = nullptr;

        std::ofstream log_file("server_log.txt", std::ios::app);
        int open_result = sqlite3_open(db_filename.c_str(), &db_connection);

        if (open_result != SQLITE_OK) {
            if (log_file.is_open()) {
                log_file << "[DB INIT ERROR] Failed to open database " << db_filename
                         << ": " << sqlite3_errmsg(db_connection) << std::endl;
            }
            sqlite3_close(db_connection);
            return;
        }

        const char* create_table_query =
            "CREATE TABLE IF NOT EXISTS key_shares ("
            "pub_key TEXT PRIMARY KEY, "
            "share_value TEXT);";

        char* error_message = nullptr;
        int exec_result = sqlite3_exec(db_connection, create_table_query, nullptr, nullptr, &error_message);

        if (exec_result != SQLITE_OK) {
            if (log_file.is_open()) {
                log_file << "[DB INIT ERROR] SQL error in database " << db_filename
                         << ": " << (error_message ? error_message : "Unknown error") << std::endl;
            }
            sqlite3_free(error_message);
            return;
        }

        sqlite3_close(db_connection);
    }
}

/**
 * @brief Clears the content of a given file without deleting the file itself.
 *
 * @param filename The path to the file to be cleared.
 */
void clearFile(const std::string& filename) {
    std::ofstream outfile(filename, std::ios::out | std::ios::trunc);
    if (!outfile.is_open()) {
        std::cerr << "Failed to open file for clearing: " << filename << std::endl;
    }
}

/**
 * @brief Inserts or updates a key share in a participant's database.
 *
 * @param participant_index Index of the participant (0-based).
 * @param public_key The public key identifier.
 * @param share_value The corresponding share value to store.
 * @return true if insertion/update was successful, false otherwise.
 */
bool storeKeyShare(int participant_index, const std::string& public_key, const std::string& share_value) {
    std::string db_filename = "storage_" + std::to_string(participant_index) + ".db";
    sqlite3* db_connection = nullptr;

    std::ofstream log_file("server_log.txt", std::ios::app);
    int open_result = sqlite3_open(db_filename.c_str(), &db_connection);

    if (open_result != SQLITE_OK) {
        if (log_file.is_open()) {
            log_file << "[DB INSERT ERROR] Failed to open database " << db_filename
                     << ": " << sqlite3_errmsg(db_connection) << std::endl;
        }
        sqlite3_close(db_connection);
        return false;
    }

    const char* insert_query = "INSERT OR REPLACE INTO key_shares (pub_key, share_value) VALUES (?, ?);";
    sqlite3_stmt* prepared_stmt = nullptr;

    int prepare_result = sqlite3_prepare_v2(db_connection, insert_query, -1, &prepared_stmt, nullptr);

    if (prepare_result != SQLITE_OK) {
        if (log_file.is_open()) {
            log_file << "[DB INSERT ERROR] Failed to prepare SQL statement in database "
                     << db_filename << ": " << sqlite3_errmsg(db_connection) << std::endl;
        }
        sqlite3_close(db_connection);
        return false;
    }

    sqlite3_bind_text(prepared_stmt, 1, public_key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(prepared_stmt, 2, share_value.c_str(), -1, SQLITE_STATIC);

    bool success = (sqlite3_step(prepared_stmt) == SQLITE_DONE);

    if (!success && log_file.is_open()) {
        log_file << "[DB INSERT ERROR] Failed to execute SQL statement for pub_key "
                 << public_key << " in database " << db_filename << std::endl;
    }

    sqlite3_finalize(prepared_stmt);
    sqlite3_close(db_connection);

    return success;
}

/**
 * @brief Retrieves a key share from a participant's database.
 *
 * @param participant_index Index of the participant (0-based).
 * @param public_key The public key identifier.
 * @return The share value as a string, or an empty string if not found or error occurred.
 */
std::string retrieveKeyShare(int participant_index, const std::string& public_key) {
    std::string db_filename = "storage_" + std::to_string(participant_index) + ".db";
    sqlite3* db_connection = nullptr;

    std::ofstream log_file("server_log.txt", std::ios::app);
    std::string share_value;

    int open_result = sqlite3_open(db_filename.c_str(), &db_connection);

    if (open_result != SQLITE_OK) {
        if (log_file.is_open()) {
            log_file << "[DB SELECT ERROR] Failed to open database " << db_filename
                     << ": " << sqlite3_errmsg(db_connection) << std::endl;
        }
        sqlite3_close(db_connection);
        return "";
    }

    const char* select_query = "SELECT share_value FROM key_shares WHERE pub_key = ?;";
    sqlite3_stmt* prepared_stmt = nullptr;

    int prepare_result = sqlite3_prepare_v2(db_connection, select_query, -1, &prepared_stmt, nullptr);

    if (prepare_result != SQLITE_OK) {
        if (log_file.is_open()) {
            log_file << "[DB SELECT ERROR] Failed to prepare SQL statement in database "
                     << db_filename << ": " << sqlite3_errmsg(db_connection) << std::endl;
        }
        sqlite3_close(db_connection);
        return "";
    }

    sqlite3_bind_text(prepared_stmt, 1, public_key.c_str(), -1, SQLITE_STATIC);

    int step_result = sqlite3_step(prepared_stmt);
    if (step_result == SQLITE_ROW) {
        const unsigned char* result_text = sqlite3_column_text(prepared_stmt, 0);
        if (result_text) {
            share_value = reinterpret_cast<const char*>(result_text);
        }
    } else {
        if (log_file.is_open()) {
            log_file << "[DB SELECT WARNING] No entry found for pub_key "
                     << public_key << " in database " << db_filename << std::endl;
        }
    }

    sqlite3_finalize(prepared_stmt);
    sqlite3_close(db_connection);

    return share_value;
}

/**
 * Convert port number to participant index.
 */
static int convertPortToParticipant(int port) {
    return port - 4999;
}

/**
 * Get filename for participant data based on key index and port.
 */
static std::string getParticipantDataFilename(int keyIndex, int port) {
    int participantId = convertPortToParticipant(port);
    return "participant_" + std::to_string(keyIndex) + std::to_string(participantId) + ".dat";
}

/**
 * Generate a random BIGNUM in the range [1, order-1].
 */
static BIGNUM* generateRandomInGroup() {
    BIGNUM* tmpOrder = BN_dup(ec_order);
    BIGNUM* randomValue = BN_new();
    if (!tmpOrder || !randomValue) {
        BN_free(tmpOrder);
        BN_free(randomValue);
        return nullptr;
    }

    BN_sub_word(tmpOrder, 1);
    BN_rand_range(randomValue, tmpOrder);
    BN_add_word(randomValue, 1);
    BN_free(tmpOrder);
    return randomValue;
}

/**
 * Append BIGNUM value (in hex) to file under a specific key.
 */
static void appendBignumToFile(const std::string& filename, const std::string& key, const BIGNUM* value) {
    std::ofstream outfile(filename, std::ios::app);
    if (!outfile.is_open()) return;

    char* hexStr = BN_bn2hex(value);
    outfile << key << ": " << hexStr << "\n";
    OPENSSL_free(hexStr);
    outfile.close();
}

/**
 * Retrieve hex value of a key from file.
 */
static std::string getBignumHexFromFile(const std::string& filename, const std::string& key) {
    std::ifstream infile(filename);
    if (!infile.is_open()) return "NOT_FOUND";

    std::string line, prefix = key + ": ";
    while (std::getline(infile, line)) {
        if (line.rfind(prefix, 0) == 0) {
            return line.substr(prefix.length());
        }
    }
    return "NOT_FOUND";
}

// === Client Request Handling ===
/**
 * Handle an incoming client request.
 */
static void handleClientRequest(int clientSocket, int port) {
    char recvBuffer[1024];
    int bytesRead = read(clientSocket, recvBuffer, sizeof(recvBuffer) - 1);
    if (bytesRead <= 0) { close(clientSocket); return; }

    recvBuffer[bytesRead] = '\0';

    std::ofstream logFile("server_log.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << "Received from port " << port << ": " << recvBuffer << std::endl;
    }

    std::istringstream iss(recvBuffer);
    std::string pubKey, command, key, value;
    iss >> pubKey >> command >> key;
    std::getline(iss, value);
    if (!value.empty() && value[0] == ' ') value.erase(0, 1);

    {
        std::lock_guard<std::mutex> lock(publicKeyMutex);
        if (publicKeyToIndex.find(pubKey) == publicKeyToIndex.end()) {
            participantCounter++;
            publicKeyToIndex[pubKey] = participantCounter;
        }
    }

    int keyIndex = publicKeyToIndex[pubKey];
    std::string filename = getParticipantDataFilename(keyIndex, port);

    if (command == "generate_k_and_y") {
        clearFile(filename);
        BIGNUM* k = generateRandomInGroup();
        BIGNUM* y = generateRandomInGroup();
        if (k && y) {
            appendBignumToFile(filename, "k", k);
            appendBignumToFile(filename, "y", y);
            send(clientSocket, "OK\n", 3, 0);
        }
        BN_free(k);
        BN_free(y);

    } else if (command == "get") {
        std::string val;
        if(key == "polynomial_secret")
        {
            val=retrieveKeyShare(convertPortToParticipant(port),pubKey);
        }
        else val = getBignumHexFromFile(filename, key);
        send(clientSocket, val.c_str(), val.size(), 0);
    } else if (command == "store") {
        if(key == "polynomial_secret")
        {
            bool success = storeKeyShare(convertPortToParticipant(port), pubKey, value);
            if (success) {
                send(clientSocket, "OK\n", 3, 0);
            } else {
                send(clientSocket, "ERROR\n", 6, 0);
            }
        }
        else{
            BIGNUM* bn = nullptr;
            BN_hex2bn(&bn, value.c_str());
            appendBignumToFile(filename, key, bn);
            BN_free(bn);
        }
    } else if (command == "compute_R") {
        BIGNUM* delta = nullptr;
        if (!BN_hex2bn(&delta, key.c_str())) {
            std::cerr << "Invalid delta hex: " << key << std::endl;
            send(clientSocket, "ERROR\n", 6, 0);
            close(clientSocket);
            return;
        }

        std::string yHex = getBignumHexFromFile(filename, "y");
        BIGNUM* yValue = nullptr;
        if (!BN_hex2bn(&yValue, yHex.c_str())) {
            std::cerr << "Failed to parse y value: " << yHex << std::endl;
            BN_free(delta);
            send(clientSocket, "ERROR\n", 6, 0);
            close(clientSocket);
            return;
        }

        BIGNUM* exponent = BN_new();
        BN_mod_mul(exponent, yValue, delta, ec_order, bn_context);

        EC_POINT* Ri = EC_POINT_new(ec_group);
        EC_POINT_mul(ec_group, Ri, exponent, nullptr, nullptr, bn_context);

        char* riHex = EC_POINT_point2hex(ec_group, Ri, POINT_CONVERSION_UNCOMPRESSED, bn_context);
        send(clientSocket, riHex, strlen(riHex), 0);

        BN_free(delta);
        BN_free(yValue);
        BN_free(exponent);
        EC_POINT_free(Ri);
        OPENSSL_free(riHex);

    } else {
        send(clientSocket, "INVALID\n", 8, 0);
    }

    close(clientSocket);
}


// === Server Loop ===
/**
 * Run the participant server on a specific port.
 */
void runParticipantServer(int port) {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        perror("Socket creation failed");
        return;
    }

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port);

    if (bind(serverSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Bind failed");
        close(serverSocket);
        return;
    }

    listen(serverSocket, 5);
    std::cout << "Participant server running on port " << port << std::endl;

    {
        std::lock_guard<std::mutex> lock(socketMapMutex);
        serverSockets[port] = serverSocket;
    }

    while (running) {
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket >= 0) {
            handleClientRequest(clientSocket, port);
        }
    }

    close(serverSocket);
    std::cout << "Closed server on port " << port << std::endl;
}
