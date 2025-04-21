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
#include <boost/asio.hpp>
#include <map>

struct Signature
{
    BIGNUM *r;
    BIGNUM *s;
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
    std::string bn_to_hex(BIGNUM* bn);
    BIGNUM* read_bn_from_file(int participantIndex, const std::string& key);
    bool append_bn_to_file(int participantIndex, const std::string& key, const BIGNUM* value);
    BIGNUM *H(const std::string& input);
    BIGNUM *H0(const EC_POINT* point);
    std::vector<BIGNUM *> generate_polynomial_t(BIGNUM *x);
    BIGNUM *evaluate_polynomial(const std::vector<BIGNUM *> &coefficients, int x);
    BIGNUM* generate_random_zq();
    void generate_participants_data(const std::vector<int> &signingGroup);
    EC_POINT* computeR(const std::vector<int> &signingGroup, BIGNUM* delta_inv);
    void compute_sigma(std::vector<int> signingGroup);

public:
    simpleECDSA(int threshold, int total_participants);
    void generateKeys();
    Signature* signMessage(BIGNUM* msgHash, const std::vector<int> &signingGroup);
    bool verifySignature(BIGNUM* msgHash, Signature* signature);
    BIGNUM* sha256_to_bn(const std::string& message);
//    ~simpleECDSA();

};

#endif // SIMPLEECDSA_HPP



