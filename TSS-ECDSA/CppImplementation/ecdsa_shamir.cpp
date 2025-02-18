#include <iostream>
#include <vector>
#include <random>
#include <stdexcept>
#include "secp256k1.h"  
#include <cstdint>

using namespace std;

=std::vector<std::vector<unsigned char>> private_key_shares;
unsigned char master_private_key[32];
unsigned char master_public_key[65];

// Helper function to calculate modular multiplicative inverse
int64_t mod_inverse(int64_t a, int64_t m) {
    int64_t m0 = m;
    int64_t y = 0, x = 1;

    if (m == 1) return 0;

    while (a > 1) {
        int64_t q = a / m;
        int64_t t = m;
        m = a % m;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }

    if (x < 0) x += m0;
    return x;
}

// Helper function for modular arithmetic
int64_t mod(int64_t a, int64_t n) {
    return ((a % n) + n) % n;
}

// Structure to hold the signature pair (r,s)
struct Signature {
    int64_t r;
    int64_t s;
};

// Structure to hold the partial signature and its index
struct PartialSignature {
    int64_t index;
    int64_t s_i;
};


class ThresholdSignature {
private:
    int64_t n; // Modulus
    vector<int64_t> x_coordinates; // x-coordinates for Lagrange interpolation

    // Calculate Lagrange basis polynomial weight
    int64_t calculate_lagrange_weight(int i, const vector<int64_t>& x_coords, int64_t n) {
        int64_t weight = 1;
        for (size_t j = 0; j < x_coords.size(); j++) {
            if (i != j) {
                int64_t numerator = x_coords[j];
                int64_t denominator = mod(x_coords[j] - x_coords[i], n);
                int64_t inv_denominator = mod_inverse(denominator, n);
                weight = mod(weight * mod(numerator * inv_denominator, n), n);
            }
        }
        return weight;
    }

public:
    ThresholdSignature(int64_t modulus) : n(modulus) {}

    // Generate partial signature for a participant
    PartialSignature generate_partial_signature(
        int64_t index,
        int64_t d_i,  // Partial private key
        int64_t k,    // Shared nonce
        int64_t r,    // R_x coordinate
        int64_t h     // Message hash
    ) {
        int64_t k_inv = mod_inverse(k, n);
        int64_t s_i = mod(k_inv * (h + r * d_i), n);

        return PartialSignature{index, s_i};
    }

    // Reconstruct the full signature from partial signatures
    Signature reconstruct_signature(
        const vector<PartialSignature>& partial_sigs,
        int64_t r
    ) {
        // Extract x-coordinates (indices) for Lagrange interpolation
        x_coordinates.clear();
        for (const auto& sig : partial_sigs) {
            x_coordinates.push_back(sig.index);
        }

        // Calculate final s using Lagrange interpolation
        int64_t s = 0;
        for (size_t i = 0; i < partial_sigs.size(); i++) {
            int64_t weight = calculate_lagrange_weight(i, x_coordinates, n);
            s = mod(s + mod(weight * partial_sigs[i].s_i, n), n);
        }

        return Signature{r, s};
    }
};

void generate_distributed_key(int n, int k) {
    if (k > n) {
        throw std::invalid_argument("Threshold k cannot be greater than the number of participants n.");
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        throw std::runtime_error("Failed to initialize secp256k1 context.");
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned char> dis(0, 255);
    for (int i = 0; i < 32; ++i) {
        master_private_key[i] = dis(gen);
    }

    std::cout << "Master private key: ";
    for (int i = 0; i < 32; ++i) {
        printf("%02x", master_private_key[i]);
    }
    std::cout << "\n";

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, master_private_key)) {
        throw std::runtime_error("Failed to create master public key.");
    }

    size_t pubkey_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, master_public_key, &pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    std::cout << "Master public key: ";
    for (size_t i = 0; i < pubkey_len; ++i) {
        printf("%02x", master_public_key[i]);
    }
    std::cout << "\n";

    private_key_shares.clear();

    std::vector<std::vector<unsigned char>> coefficients(k - 1, std::vector<unsigned char>(32));
    for (int i = 0; i < k - 1; ++i) {
        for (int j = 0; j < 32; ++j) {
            coefficients[i][j] = dis(gen);
        }
    }

    for (int x = 1; x <= n; ++x) {
        std::vector<unsigned char> share(32, 0);
        for (int j = 0; j < 32; ++j) {
            unsigned char value = master_private_key[j];
            unsigned char x_pow = 1;

            for (int i = 0; i < k - 1; ++i) {
                value ^= coefficients[i][j] * x_pow;
                x_pow *= x;
            }

            share[j] = value;
        }
        private_key_shares.push_back(share);

        std::cout << "Private key share for participant " << x << ": ";
        for (int j = 0; j < 32; ++j) {
            printf("%02x", share[j]);
        }
        std::cout << "\n";
    }

    secp256k1_context_destroy(ctx);
}

