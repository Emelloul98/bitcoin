// === ParticipantServer.cpp ===

#include "ParticipantServer.h"
#include <fstream>

EC_GROUP* group = nullptr;
BIGNUM* order = nullptr;
BN_CTX* ctx = nullptr;

//static std::unordered_map<int, int> store_count;
//static std::unordered_map<std::string, std::string> key_to_filename;
static std::unordered_map<std::string, int> pubkey_to_id;
static int next_pubkey_id = 1;

int port_to_participant(int port) {
    return port - 4999;
}

std::string get_filename_for_port(int port, const std::string& pubkey_hex) {

    if (pubkey_to_id.find(pubkey_hex) == pubkey_to_id.end()) {
        pubkey_to_id[pubkey_hex] = next_pubkey_id++;
    }

    int participant_id = pubkey_to_id[pubkey_hex];
    int participant_number = port_to_participant(port);

    return "participant_" + std::to_string(participant_id) + std::to_string(participant_number) + ".dat";
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

    std::ofstream log_file("server_log.txt", std::ios::app); // פתיחה ב־append mode
    if (log_file.is_open()) {
        log_file << "Received from port " << port << ": " << buffer << std::endl;
        log_file.close();
    }
    std::istringstream iss(buffer);
    std::string command, key, value , pubkey_hex;
    iss >> command;
    if(command == "store")
    {
        iss >> key >> value >> pubkey_hex;
    }
    else if(command =="generate_k_and_y")
    {
        iss >> pubkey_hex;
    }
    else {
        iss >> key >> pubkey_hex;
    }
    if (!value.empty() && value[0] == ' ') value.erase(0, 1);

    std::string filename = get_filename_for_port(port,pubkey_hex);

    if (command == "generate_k_and_y") {
        std::ifstream infile(filename);
        std::string line, saved_polynomial_secret;
        while (std::getline(infile, line)) {
            if (line.find("polynomial_secret") == 0) {
                saved_polynomial_secret = line;
                break;
            }
        }
        infile.close();

        std::ofstream outfile(filename, std::ios::trunc);
        if (!saved_polynomial_secret.empty()) {
            outfile << saved_polynomial_secret << std::endl;
        }
        outfile.close();

        BIGNUM* k = generate_random_zq(order);
        BIGNUM* y = generate_random_zq(order);
        append_bn_to_file(filename, "k", k);
        append_bn_to_file(filename, "y", y);
        BN_free(k);
        BN_free(y);
        send(client_socket, "OK\n", 3, 0);
    } else if (command == "get") {
        std::string val = get_bn_from_file(filename, key);
        send(client_socket, val.c_str(), val.size(), 0);
    } else if (command == "store") {
        BIGNUM* bn = nullptr;
        BN_hex2bn(&bn, value.c_str());
        append_bn_to_file(filename, key, bn);
        BN_free(bn);
        send(client_socket, "OK\n", 3, 0);
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
