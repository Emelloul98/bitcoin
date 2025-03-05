#include <iostream>
#include <vector>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <fstream>


using json = nlohmann::json;

struct Participant {
    BIGNUM* ui;
    BIGNUM* ki;
    BIGNUM* wi;
    BIGNUM* xi;

    BIGNUM* gamma_i;
    BIGNUM* sigma_i;
    BIGNUM* delta_i;
    BIGNUM* s_i;
    EC_POINT* yi;
    std::vector<BIGNUM*> polynomial;
    std::vector<BIGNUM*> shares;
    int participant_id;
}

 BIGNUM *generate_random_zq(BIGNUM *order)
    {
        BIGNUM *rand = BN_new();
        BN_rand_range(rand, order);
        return rand;
    }

BIGNUM *hash_message(const std::string &message)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, message.c_str(), message.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);

    BIGNUM *bnHash = BN_new();
    BN_bin2bn(hash, hash_len, bnHash);

    EVP_MD_CTX_free(ctx);
    return bnHash;
}

