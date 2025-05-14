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

void create_DB(int n)
{
    for (int i = 0; i < n; ++i) {
        std::string db_name = "storage_" + std::to_string(i+1) + ".db";
        sqlite3* db;
        std::ofstream log_file("server_log.txt", std::ios::app);
        int rc = sqlite3_open(db_name.c_str(), &db);
        if (rc) {
            if (log_file.is_open()) {
                log_file << "[DB INIT ERROR] Failed to open database " << db_name
                         << ": " << sqlite3_errmsg(db) << std::endl;
            }
            return;
        }
        const char* create_table_sql = "CREATE TABLE IF NOT EXISTS key_shares (pub_key TEXT PRIMARY KEY, share_value TEXT);";
        sqlite3_exec(db, create_table_sql, nullptr, nullptr, nullptr);
        if (rc != SQLITE_OK) {
            if (log_file.is_open()) {
                log_file << "[DB INIT ERROR] SQL error in database " << db_name
                         << ": " << sqlite3_errmsg(db) << std::endl;
            }
            return;
        }
        sqlite3_close(db);
    }
}

bool insert_key_share(int participant_index, const std::string& pub_key, const std::string& share_value) {
    std::string db_name = "storage_" + std::to_string(participant_index) + ".db";
    sqlite3* db;
    std::ofstream log_file("server_log.txt", std::ios::app);
    if (sqlite3_open(db_name.c_str(), &db) != SQLITE_OK) {
        if (log_file.is_open()) {
            log_file << "[DB INSERT ERROR] Failed to open database " << db_name
                     << ": " << sqlite3_errmsg(db) << std::endl;
        }
        return false;
    }

    std::string sql = "INSERT OR REPLACE INTO key_shares (pub_key, share_value) VALUES (?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        if (log_file.is_open()) {
            log_file << "[DB INSERT ERROR] Failed to prepare SQL statement in database "
                     << db_name << ": " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_close(db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, pub_key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, share_value.c_str(), -1, SQLITE_STATIC);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    if (!success && log_file.is_open()) {
        log_file << "[DB INSERT ERROR] Failed to execute SQL statement for pub_key "
                 << pub_key << " in database " << db_name << std::endl;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return success;
}

std::string get_key_share(int participant_index, const std::string& pub_key) {
    std::string db_name = "storage_" + std::to_string(participant_index) + ".db";
    sqlite3* db;
    std::ofstream log_file("server_log.txt", std::ios::app);
    std::string share_value;

    if (sqlite3_open(db_name.c_str(), &db) != SQLITE_OK) {
        if (log_file.is_open()) {
            log_file << "[DB SELECT ERROR] Failed to open database " << db_name
                     << ": " << sqlite3_errmsg(db) << std::endl;
        }
        return "";
    }

    std::string sql = "SELECT share_value FROM key_shares WHERE pub_key = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        if (log_file.is_open()) {
            log_file << "[DB SELECT ERROR] Failed to prepare SQL statement in database "
                     << db_name << ": " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_close(db);
        return "";
    }

    sqlite3_bind_text(stmt, 1, pub_key.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text) {
            share_value = reinterpret_cast<const char*>(text);
        }
    } else {
        if (log_file.is_open()) {
            log_file << "[DB SELECT WARNING] No entry found for pub_key "
                     << pub_key << " in database " << db_name << std::endl;
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

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
            val=get_key_share(convertPortToParticipant(port),pubKey);
        }
        else val = getBignumHexFromFile(filename, key);
        send(clientSocket, val.c_str(), val.size(), 0);
    } else if (command == "store") {
        if(key == "polynomial_secret")
        {
            bool success = insert_key_share(convertPortToParticipant(port), pubKey, value);
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
