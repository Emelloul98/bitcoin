// === ParticipantServer.cpp ===
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "ParticipantServer.h"
#include <sqlite3.h>
EC_GROUP* group;
BIGNUM* order;
BN_CTX* ctx;
static std::unordered_map<std:: string, int> pub_key_to_num;
static int participant_id = 0;
static int n_value;

void create_DB(int n)
{
    n_value=n;
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


int port_to_participant(int port) {
    return port - 4999;
}

std::string get_filename_for_port(int index_key, int port) {
    int participant = port_to_participant(port);
    return "participant_" + std::to_string(index_key) + std::to_string(participant) + ".dat";
}

BIGNUM* generate_random_zq(const BIGNUM* order) {
    BIGNUM* ord = BN_dup(order);
    BN_sub_word(ord, 1);
    BIGNUM* res = BN_new();
    BN_rand_range(res, ord);
    BN_add_word(res, 1);
    BN_free(ord);
    return res;
}



void append_bn_to_file(const std::string& filename, const std::string& key, const BIGNUM* value) {
    std::ofstream outfile(filename, std::ios::app);
    char* hex = BN_bn2hex(value);
    outfile << key << ": " << hex << "\n";
    OPENSSL_free(hex);
    outfile.close();
}

std::string get_bn_from_file(const std::string& filename, const std::string& key) {
    std::ifstream infile(filename);
    std::string line, prefix = key + ": ";
    while (std::getline(infile, line)) {
        if (line.rfind(prefix, 0) == 0) {
            return line.substr(prefix.length());
        }
    }
    return "NOT_FOUND";
}

void handle_client(int client_socket, int port, const BIGNUM* order) {
    char buffer[1024];
    int read_bytes = read(client_socket, buffer, sizeof(buffer) - 1);
    if (read_bytes <= 0) { close(client_socket); return; }

    buffer[read_bytes] = '\0';

    std::ofstream log_file("server_log.txt", std::ios::app);
    if (log_file.is_open()) {
        log_file << "Received from port " << port << ": " << buffer << std::endl;
        log_file.close();
    }
    std::istringstream iss(buffer);
    std::string pubKey, command, key, value;
    iss >> pubKey >> command >> key;
    std::getline(iss, value);
    if (!value.empty() && value[0] == ' ') value.erase(0, 1);

    if (pub_key_to_num.find(pubKey) == pub_key_to_num.end()) {
        participant_id++;
        pub_key_to_num[pubKey] = participant_id;
    }
    int ind = pub_key_to_num[pubKey];
    std::string filename = get_filename_for_port(ind, port);

    if (command == "generate_k_and_y") {
        BIGNUM* k = generate_random_zq(order);
        BIGNUM* y = generate_random_zq(order);
        append_bn_to_file(filename, "k", k);
        append_bn_to_file(filename, "y", y);
        BN_free(k);
        BN_free(y);
        send(client_socket, "OK\n", 3, 0);
    } else if (command == "get") {
        std::string val;
        if(key == "polynomial_secret")
        {
            val=get_key_share(port_to_participant(port),pubKey);
        }
        else val = get_bn_from_file(filename, key);
        send(client_socket, val.c_str(), val.size(), 0);
    } else if (command == "store") {
        if(key == "polynomial_secret")
        {
            bool success = insert_key_share(port_to_participant(port), pubKey, value);
            if (success) {
                send(client_socket, "OK\n", 3, 0);
            } else {
                send(client_socket, "ERROR\n", 6, 0);
            }
        }
        else{
            BIGNUM* bn = nullptr;
            BN_hex2bn(&bn, value.c_str());
            append_bn_to_file(filename, key, bn);
            BN_free(bn);
        }
    }else if (command == "compute_R") {

        BIGNUM* delta = nullptr;
        BN_hex2bn(&delta, key.c_str());

        BIGNUM* y = nullptr;
        std::string y_val = get_bn_from_file(filename, "y");

        if (!BN_hex2bn(&y, y_val.c_str())) {
            std::cerr << "BN_hex2bn failed for y_val: " << y_val << std::endl;
            close(client_socket);
            return;
        }

        BIGNUM* exp = BN_new();
        BN_mod_mul(exp, y, delta, order, ctx);

        EC_POINT* Ri = EC_POINT_new(group);
        EC_POINT_mul(group, Ri, exp, nullptr, nullptr, ctx); // Ri = g^exp

        char* Ri_hex = EC_POINT_point2hex(group, Ri, POINT_CONVERSION_UNCOMPRESSED, ctx);
        send(client_socket, Ri_hex, strlen(Ri_hex), 0);

        BN_free(delta); BN_free(y); BN_free(exp);
        EC_POINT_free(Ri); OPENSSL_free(Ri_hex);
    }else {
        send(client_socket, "INVALID\n", 8, 0);
    }

    close(client_socket);
}

void run_server(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    bind(server_fd, (sockaddr*)&address, sizeof(address));
    listen(server_fd, 5);
    std::cout << "Participant server on port " << port << std::endl;


    while (true) {
        int client_socket = accept(server_fd, nullptr, nullptr);
        handle_client(client_socket, port, order);
    }


    close(server_fd);
}

