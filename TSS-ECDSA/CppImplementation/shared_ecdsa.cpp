#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cassert>
#include <openssl/sha.h>
#include <openssl/evp.h>

// Global variable for public key
EC_POINT* global_public_key = nullptr;
EC_GROUP* group = nullptr;

// Structure to hold a share
struct KeyShare {
    BIGNUM* x;  // x-coordinate
    BIGNUM* y;  // share value
};

// Function to generate random polynomial coefficients
std::vector<BIGNUM*> generate_polynomial(const BIGNUM* secret, int threshold) {
    std::vector<BIGNUM*> coefficients;
    coefficients.push_back(BN_dup(secret));
    
    for(int i = 1; i < threshold; i++) {
        BIGNUM* coeff = BN_new();
        BN_rand(coeff, 256, -1, 0);
        coefficients.push_back(coeff);
    }
    return coefficients;
}
