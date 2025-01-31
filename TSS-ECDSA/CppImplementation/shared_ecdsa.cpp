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


// Helper function to clean up shares
void cleanup_shares(std::vector<KeyShare>& shares) {
    for(auto& share : shares) {
        BN_free(share.x);
        BN_free(share.y);
    }
    if(global_public_key) {
        EC_POINT_free(global_public_key);
    }
    if(group) {
        EC_GROUP_free(group);
    }
}

BIGNUM* generate_deterministic_k(const std::string& message, const BIGNUM* private_key) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, message.c_str(), message.length());
    
    unsigned char hash[32];
    unsigned int hash_len;
    EVP_DigestFinal_ex(md_ctx, hash, &hash_len);
    EVP_MD_CTX_free(md_ctx);
    
    BIGNUM* k = BN_new();
    BN_bin2bn(hash, hash_len, k);
    
    BN_CTX* ctx = BN_CTX_new();
    BN_mod(k, k, EC_GROUP_get0_order(group), ctx);
    BN_CTX_free(ctx);
    
    return k;
}

ECDSA_SIG* partial_sign(const std::string& file_path, const std::string& message, const BIGNUM* k = nullptr) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open share file");
    }

    std::string x_str, y_str;
    std::getline(file, x_str);
    std::getline(file, y_str);
    file.close();


    BIGNUM* x = nullptr;
    BIGNUM* share = nullptr;
    BN_hex2bn(&x, x_str.c_str());
    BN_hex2bn(&share, y_str.c_str());

    unsigned char hash[32];
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, message.c_str(), message.length());
    unsigned int hash_len;
    EVP_DigestFinal_ex(md_ctx, hash, &hash_len);
    EVP_MD_CTX_free(md_ctx);

    BIGNUM* k_owned = nullptr;
    if (!k) {
        k_owned = generate_deterministic_k(message, share);
        k = k_owned;
    }
    
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    
    EC_POINT* R = EC_POINT_new(group);
    BN_CTX* ctx = BN_CTX_new();
    
    EC_POINT_mul(group, R, k, nullptr, nullptr, ctx);
    EC_POINT_get_affine_coordinates(group, R, r, nullptr, ctx);
    
    BIGNUM* k_inv = BN_new();
    BN_mod_inverse(k_inv, k, EC_GROUP_get0_order(group), ctx);
    
    BIGNUM* hash_bn = BN_bin2bn(hash, hash_len, nullptr);
    BIGNUM* temp = BN_new();
    
    BN_mod_mul(temp, r, share, EC_GROUP_get0_order(group), ctx);
    BN_mod_add(temp, hash_bn, temp, EC_GROUP_get0_order(group), ctx);
    BN_mod_mul(s, k_inv, temp, EC_GROUP_get0_order(group), ctx);
    
    ECDSA_SIG_set0(sig, r, s);
    
    if (k_owned) BN_free(k_owned);
    BN_free(x);
    BN_free(share);
    BN_free(k_inv);
    BN_free(hash_bn);
    BN_free(temp);
    EC_POINT_free(R);
    BN_CTX_free(ctx);
    
    return sig;
}

ECDSA_SIG* create_combined_signature(const std::vector<ECDSA_SIG*>& partial_signatures) {
    // Initialize r and s as BIGNUM objects
    BIGNUM* r_combined = BN_new();
    BIGNUM* s_combined = BN_new();
    BN_zero(r_combined);
    BN_zero(s_combined);

    // Combine r and s from each partial signature
    for (size_t i = 0; i < partial_signatures.size(); i++) {
        const BIGNUM* r_part;
        const BIGNUM* s_part;
        ECDSA_SIG_get0(partial_signatures[i], &r_part, &s_part);

        // Combine r
        BN_add(r_combined, r_combined, r_part);
        BN_mod(r_combined, r_combined, EC_GROUP_get0_order(group), BN_CTX_new());

        // Combine s
        BN_add(s_combined, s_combined, s_part);
        BN_mod(s_combined, s_combined, EC_GROUP_get0_order(group), BN_CTX_new());
    }

    // Create the combined signature
    ECDSA_SIG* combined_sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(combined_sig, r_combined, s_combined);

    return combined_sig;
}

int main() {
    try {
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (!group) {
            throw std::runtime_error("Failed to create EC_GROUP");
        }

        // Create shares: 5 total with threshold of 3
        int n = 5, t = 3;
        std::vector<KeyShare> shares = create_threshold_ecdsa(n, t);
        
        // Verify we got correct number of shares
        assert(shares.size() == n);
        
        // Print public key
        BN_CTX* ctx = BN_CTX_new();
        char* pub_key_hex = EC_POINT_point2hex(group, global_public_key, 
                                             POINT_CONVERSION_COMPRESSED, ctx);
        std::cout << "Public Key: " << pub_key_hex << std::endl;
        OPENSSL_free(pub_key_hex);
        BN_CTX_free(ctx);
        
    

        // Print share info
        for(size_t i = 0; i < shares.size(); i++) {
            char* x_hex = BN_bn2hex(shares[i].x);
            char* y_hex = BN_bn2hex(shares[i].y);
            std::cout << "Share " << i+1 << ":\n";
            std::cout << "  x: " << x_hex << "\n";
            std::cout << "  y: " << y_hex << "\n";
            OPENSSL_free(x_hex);
            OPENSSL_free(y_hex);
        }
        
        // Generate three partial signatures
        std::vector<ECDSA_SIG*> signatures;
        const std::string message = "Hello, World!";
        std::cout << "\nGenerating partial signatures for message: " << message << "\n\n";
        
        BIGNUM* k = generate_deterministic_k(message, shares[0].y);

        for(int i = 1; i <= t; i++) {
            std::string share_file = "share_" + std::to_string(i) + ".txt";
            ECDSA_SIG* sig = partial_sign(share_file, message, k);
            signatures.push_back(sig);

            // Print signature components
            const BIGNUM *r, *s;
            ECDSA_SIG_get0(sig, &r, &s);
            char* r_hex = BN_bn2hex(r);
            char* s_hex = BN_bn2hex(s);
            std::cout << "Partial Signature " << i << ":\n";
            std::cout << "  r: " << r_hex << "\n";
            std::cout << "  s: " << s_hex << "\n\n";
            OPENSSL_free(r_hex);
            OPENSSL_free(s_hex);
        }

        ECDSA_SIG* combined_signature = create_combined_signature(signatures);
        // הדפסת החתימה המשותפת
        const BIGNUM *r_combined, *s_combined;
        ECDSA_SIG_get0(combined_signature, &r_combined, &s_combined);
        char* r_hex = BN_bn2hex(r_combined);
        char* s_hex = BN_bn2hex(s_combined);
        std::cout << "Combined Signature:\n";
        std::cout << "  r: " << r_hex << "\n";
        std::cout << "  s: " << s_hex << "\n";

        // שחרור המשאבים
        OPENSSL_free(r_hex);
        OPENSSL_free(s_hex);

        ECDSA_SIG_free(combined_signature);

        
        // Cleanup signatures
        for(auto sig : signatures) {
            ECDSA_SIG_free(sig);
        }
        // Cleanup
        cleanup_shares(shares);
        return 0;
        EC_GROUP_free(group);

    }
    catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
