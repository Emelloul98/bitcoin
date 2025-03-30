#ifndef SIMPLEECDSA_HPP
#define SIMPLEECDSA_HPP

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <cstring>


struct Participant
{
    BIGNUM *y;
    BIGNUM *k;
    BIGNUM *x;
    BIGNUM *w;

    BIGNUM *sigma;
    BIGNUM *s;
    BIGNUM *gamma;
    int participant_id;


    Participant() {
        y = BN_new();
        k = BN_new(); 
        x = BN_new();
        w = BN_new();
        sigma = BN_new();
        s = BN_new();
        gamma = BN_new();
        BN_one(gamma);
        participant_id = -1;
     }

     ~Participant() {
        BN_free(y);
        BN_free(k);
        BN_free(x);
        BN_free(w);
        BN_free(sigma);
        BN_free(s);
        BN_free(gamma);
        
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


class simpleECDSA {
private:
    const EC_GROUP *group;
    BIGNUM *order;
    EC_POINT *generator;
    EC_POINT *publicKey;
    BN_CTX *ctx;

    int t;
    int n;
    std::vector<Participant*> participants;

    BIGNUM *H(const std::string& input);
    BIGNUM *H0(const EC_POINT* point);

    BIGNUM* generate_random_zq();
    std::vector<BIGNUM *> generate_polynomial_t(BIGNUM *x);
    BIGNUM *evaluate_polynomial(const std::vector<BIGNUM *> &coefficients, int x);
    void generate_participants_data(const std::vector<int> &signingGroup);
    EC_POINT* computeR(const std::vector<int> &signingGroup, BIGNUM* delta_inv);
    void compute_sigma(std::vector<int> signingGroup);

public:
    simpleECDSA(int threshold, int total_participants);
    void generateKeys();
    Signature* signMessage(const std::string& message, const std::vector<int> &signingGroup);
    bool verifySignature(const std::string& message, Signature* signature);
    EC_POINT* getPublicKey(){
        return publicKey;
    }
//    ~simpleECDSA();

};

#endif // SIMPLEECDSA_HPP



