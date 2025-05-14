#ifndef DISTRIBUTEDSIGNER_H
#define DISTRIBUTEDSIGNER_H

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <map>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>


struct Signature {
    BIGNUM* r;
    BIGNUM* s;
};

class DistributedSigner {
private:
    static const int t = 2;
    static const int n = 3;
    static BIGNUM* order;
    static EC_GROUP* group;
    static BN_CTX* ctx;


    struct CleanupHelper {
        ~CleanupHelper() {
            EC_GROUP_free(group);
            BN_free(order);
            BN_CTX_free(ctx);
        }
    };
    static CleanupHelper cleanup_guard;
    static std::string send_to_participant(std::string pub_str, int port, const std::string& message);
    static BIGNUM* str_to_bn(const std::string& hex);
    static BIGNUM* H0(const EC_POINT* point);
    static std::vector<BIGNUM *> generate_polynomial_t(BIGNUM *x);
    static BIGNUM *evaluate_polynomial(const std::vector<BIGNUM *> &coefficients, int x);
    static BIGNUM* generate_random_zq();
    static void compute_sigma(std::string pub_str, const std::vector<int>& ports);


public:

    static void generateKeys(std::string pub_str, BIGNUM *privateKey);
    static Signature* signMessage(std::string pub_str, BIGNUM* msgHash, const std::vector<int>& ports);
    static void cleanup();

};
#endif //DISTRIBUTEDSIGNER_H


