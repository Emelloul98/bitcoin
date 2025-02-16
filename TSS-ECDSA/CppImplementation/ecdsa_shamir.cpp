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
