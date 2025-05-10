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
