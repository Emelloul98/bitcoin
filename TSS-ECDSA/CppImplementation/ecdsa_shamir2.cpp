#include <iostream>
#include <vector>
#include <random>
#include <cassert>
#include <secp256k1.h>
#include <algorithm>
#include <openssl/sha.h> 
#include <openssl/bn.h>



struct Participant {
    int id;        
    BIGNUM* privateKeyPart; 
    BIGNUM* nonce;          
    secp256k1_pubkey Ri;    
    BIGNUM* r_x;         
};

//TODO add n to struct


BIGNUM* computePartialSignature(
    const Participant& participant,
    const BIGNUM* z,
    const BIGNUM* n,
    BN_CTX* ctx
) {
    BIGNUM* k_inverse = BN_new();
    BIGNUM* r_mul_d_i = BN_new();
    BIGNUM* z_plus_r_di = BN_new();
    BIGNUM* s_i = BN_new();

    if (!BN_mod_inverse(k_inverse, participant.nonce, n, ctx)) {
        throw std::runtime_error("Failed to compute modular inverse");
    }

    if (!BN_mod_mul(r_mul_d_i, participant.r_x, participant.privateKeyPart, n, ctx)) {
        throw std::runtime_error("Failed to compute r * d_i mod n");
    }

    if (!BN_mod_add(z_plus_r_di, z, r_mul_d_i, n, ctx)) {
        throw std::runtime_error("Failed to compute z + r * d_i mod n");
    }

    if (!BN_mod_mul(s_i, k_inverse, z_plus_r_di, n, ctx)) {
        throw std::runtime_error("Failed to compute partial signature");
    }

    BN_free(k_inverse);
    BN_free(r_mul_d_i);
    BN_free(z_plus_r_di);

    return s_i;
}

