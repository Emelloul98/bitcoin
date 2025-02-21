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

BIGNUM* combineSignatures(const std::vector<BIGNUM*>& partialSignatures, BIGNUM* n, BN_CTX* ctx) { 
    BIGNUM* combinedSignature = BN_new();
    BN_zero(combinedSignature);

    for (const auto& s_i : partialSignatures) {
        if (!BN_mod_add(combinedSignature, combinedSignature, s_i, n, ctx)) {
            throw std::runtime_error("Failed to combine partial signatures");
        }
    }

    return combinedSignature;
}

int main() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    assert(ctx);

    BN_CTX* bn_ctx = BN_CTX_new();
    assert(bn_ctx);

    int numParticipants = 5; 

    BIGNUM* globalPrivateKey = BN_new();
    BN_rand(globalPrivateKey, 256, 0, 0);

    BIGNUM* secp256k1_order = BN_new();
    BN_hex2bn(&secp256k1_order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    std::vector<Participant> participants = initializeParticipants(numParticipants, globalPrivateKey, secp256k1_order, ctx, bn_ctx);

    for (const auto& participant : participants) {
        std::cout << "Participant ID: " << participant.id << "\n";
        std::cout << "Private Key Part: " << BN_bn2hex(participant.privateKeyPart) << "\n";
        std::cout << "Nonce: " << BN_bn2hex(participant.nonce) << "\n";
    }

    std::string message = "This is a real message to sign.";

    unsigned char hash[32];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), hash);
    BIGNUM* z = BN_bin2bn(hash, 32, nullptr);

    std::vector<BIGNUM*> partialSignatures;
    for (const auto& participant : participants) {
        BIGNUM* s_i = computePartialSignature(participant, z, secp256k1_order, bn_ctx);
        partialSignatures.push_back(s_i);
    }

    for (size_t i = 0; i < partialSignatures.size(); ++i) {
        std::cout << "Participant " << participants[i].id << " Partial Signature: " << BN_bn2hex(partialSignatures[i]) << "\n";
    }

    BIGNUM* finalSignature = combineSignatures(partialSignatures, secp256k1_order, bn_ctx);

    std::cout << "Final Signature: " << BN_bn2hex(finalSignature) << std::endl;

    BN_free(finalSignature);

    BN_free(globalPrivateKey);
    BN_free(secp256k1_order);
    BN_free(z);
    for (auto& signature : partialSignatures) {
        BN_free(signature);
    }
    for (auto& participant : participants) {
        BN_free(participant.privateKeyPart);
        BN_free(participant.nonce);
        BN_free(participant.r_x);
    }
    BN_CTX_free(bn_ctx);
    secp256k1_context_destroy(ctx);

    return 0;
}

