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

Participant createParticipant(int id, BIGNUM* privateKeyPart, secp256k1_context* ctx) {
    Participant participant;
    participant.id = id;

    participant.privateKeyPart = BN_dup(privateKeyPart);

    participant.nonce = BN_new();
    BN_rand(participant.nonce, 256, 0, 0);

    unsigned char nonceBytes[32];
    BN_bn2binpad(participant.nonce, nonceBytes, 32);
    int success = secp256k1_ec_pubkey_create(ctx, &participant.Ri, nonceBytes);
    assert(success);

    participant.r_x = BN_new();

    return participant;
}

std::vector<Participant> initializeParticipants(
    int numParticipants,
    BIGNUM* globalPrivateKey,
    BIGNUM* n, 
    secp256k1_context* ctx,
    BN_CTX* bn_ctx
) {
    std::vector<Participant> participants;

    std::vector<BIGNUM*> privateKeyParts(numParticipants, nullptr);
    for (int i = 0; i < numParticipants - 1; ++i) {
        privateKeyParts[i] = BN_new();
        BN_rand_range(privateKeyParts[i], n);
    }

    privateKeyParts[numParticipants - 1] = BN_new();
    BN_copy(privateKeyParts[numParticipants - 1], globalPrivateKey);
    for (int i = 0; i < numParticipants - 1; ++i) {
        BN_mod_sub(privateKeyParts[numParticipants - 1],
                   privateKeyParts[numParticipants - 1],
                   privateKeyParts[i],
                   n,
                   bn_ctx);
    }

    for (int i = 0; i < numParticipants; ++i) {
        participants.push_back(createParticipant(i, privateKeyParts[i], ctx));
    }

    secp256k1_pubkey globalR;
    std::vector<const secp256k1_pubkey*> pubkeys;
    for (const auto& participant : participants) {
        pubkeys.push_back(&participant.Ri);
    }

    int success = secp256k1_ec_pubkey_combine(ctx, &globalR, pubkeys.data(), pubkeys.size());
    assert(success);

    unsigned char globalR_compressed[33];
    size_t compressedSize = sizeof(globalR_compressed);
    success = secp256k1_ec_pubkey_serialize(
        ctx, globalR_compressed, &compressedSize, &globalR, SECP256K1_EC_COMPRESSED);
    assert(success);

    BIGNUM* globalRx = BN_new();
    BN_bin2bn(globalR_compressed + 1, 32, globalRx);

    for (auto& participant : participants) {
        participant.r_x = BN_dup(globalRx);
    }

    BN_free(globalRx);
    for (auto& part : privateKeyParts) {
        BN_free(part);
    }

    return participants;
}
