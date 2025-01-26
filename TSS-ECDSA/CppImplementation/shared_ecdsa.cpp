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

// Function to evaluate polynomial at point x
BIGNUM* evaluate_polynomial(const std::vector<BIGNUM*>& coefficients, const BIGNUM* x, BN_CTX* ctx) {
    BIGNUM* result = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* x_power = BN_new();
    
    BN_copy(result, coefficients[0]);
    BN_one(x_power);
    
    for(size_t i = 1; i < coefficients.size(); i++) {
        BN_mul(x_power, x_power, x, ctx);
        BN_mul(temp, coefficients[i], x_power, ctx);
        BN_add(result, result, temp);
    }
    
    BN_free(temp);
    BN_free(x_power);
    return result;
}

// Main function to create threshold ECDSA shares
std::vector<KeyShare> create_threshold_ecdsa(int n, int t) {
    std::vector<KeyShare> shares;
    BN_CTX* ctx = BN_CTX_new();
    
    // Initialize the curve
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    const BIGNUM* order = EC_GROUP_get0_order(group);
    
    // Generate private key
    BIGNUM* private_key = BN_new();
    BN_rand_range(private_key, order);
    
    // Generate polynomial coefficients
    std::vector<BIGNUM*> coefficients = generate_polynomial(private_key, t);
    
    // Generate shares
    for(int i = 1; i <= n; i++) {
        KeyShare share;
        share.x = BN_new();
        BN_set_word(share.x, i);
        
        share.y = evaluate_polynomial(coefficients, share.x, ctx);
        
        // Save share to file
        std::string filename = "share_" + std::to_string(i) + ".txt";
        std::ofstream file(filename);
        char* x_str = BN_bn2hex(share.x);
        char* y_str = BN_bn2hex(share.y);
        file << x_str << "\n" << y_str;
        file.close();
        OPENSSL_free(x_str);
        OPENSSL_free(y_str);
        
        shares.push_back(share);
    }
    
    // Generate public key
    global_public_key = EC_POINT_new(group);
    EC_POINT_mul(group, global_public_key, private_key, nullptr, nullptr, ctx);
    
    // Clean up
    BN_free(private_key);
    for(auto coeff : coefficients) {
        BN_free(coeff);
    }
    BN_CTX_free(ctx);
    
    return shares;
}
