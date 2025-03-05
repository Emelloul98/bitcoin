#ifndef THRESHOLDECDSA_HPP
#define THRESHOLDECDSA_HPP

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct Participant
{
    BIGNUM *u;
    BIGNUM *k;
    BIGNUM *w;
    BIGNUM *x;

    BIGNUM *gamma;
    BIGNUM *sigma;
    BIGNUM *delta;
    BIGNUM *s;
    EC_POINT *y;
    std::vector<BIGNUM *> shares;
    int participant_id;


    Participant() {
        u = BN_new();
        k = BN_new(); 
        w = BN_new();
        x = BN_new();
        gamma = BN_new();
        sigma = BN_new();
        delta = BN_new();
        s = BN_new();
        y = nullptr;
        participant_id = -1;
     }

     ~Participant() {
        BN_free(u);
        BN_free(k);
        BN_free(w);
        BN_free(x);
        BN_free(gamma);
        BN_free(sigma);
        BN_free(delta);
        BN_free(s);
        if (y) EC_POINT_free(y);
        if (!shares.empty()) {
        for (auto share : shares) {
                BN_free(share);
            }
        }
     }
};

struct Signature
{
    BIGNUM *r;
    BIGNUM *s;

    //~Signature() TODO
    //{
    //    BN_free(r);
    //   BN_free(s);
    //}
};
class ThresholdECDSA {
private:
    const EC_GROUP *group;
    BIGNUM *order;
    EC_POINT *generator;
    EC_POINT *publicKey;
    int t;
    int n;
    std::vector<Participant*> participants;

    BIGNUM* generate_random_zq();
    std::vector<BIGNUM *> generate_polynomial_t(BIGNUM *ui);
    BIGNUM *evaluate_polynomial(const std::vector<BIGNUM *> &coefficients, int x);
    void generate_participant_data(int participant_id, Participant &data);
    void generateSignatureShares(const std::vector<int> &signingGroup);
    ECDSA_SIG * combineSignatureShares(const std::vector<int> &signingGroup, const BIGNUM *messageHash);
    void saveToFile(const std::string &filename);


public:
    ThresholdECDSA(int threshold, int total_participants);
    EC_POINT * generateKeys();
    ECDSA_SIG * signMessage(const char *message, size_t message_length, const std::vector<int> &signingGroup,BIGNUM* msgHash);
    //bool verifySignature(const std::string &messageHex, const json &signature);
    ~ThresholdECDSA();

};

#endif // THRESHOLDECDSA_HPP


