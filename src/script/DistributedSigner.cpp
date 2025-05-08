#include "DistributedSigner.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cstring>
#include <iostream>


#include <openssl/hmac.h>
#include <cstring>

//Hash function H0: maps an elliptic curve point to an integer in Zq
BIGNUM* DistributedSigner::H0(const EC_POINT* point) {
    BIGNUM* x = BN_new();
    BIGNUM* result = BN_new();

    if (!x || !result || !EC_POINT_get_affine_coordinates(group, point, x, nullptr, ctx)) {
        if (x) BN_free(x);
        if (result) BN_free(result);
        return nullptr;
    }

    BN_mod(result, x, order, ctx);
    BN_free(x);
    return result;
}


BIGNUM *DistributedSigner::generate_random_zq()
{
    BIGNUM *res = BN_new();
    BIGNUM *ord = BN_new();
    // Copy the value of 'order' to 'ord'
    BN_copy(ord, order);
    // Subtract 1 from ord (this modifies ord in place)
    BN_sub_word(ord, 1);
    // Generate a random number in the range [0, order-2]
    BN_rand_range(res, ord);
    // Ensure the result is in the desired range [1, order-1] by adding 1
    BN_add_word(res, 1);
    BN_free(ord);
    return res;
}


std::vector<BIGNUM *> DistributedSigner::generate_polynomial_t(BIGNUM *x)
{ //offline
    std::vector<BIGNUM *> coefficients;
    coefficients.push_back(BN_dup(x));
    for (int i = 1; i < t; i++)
    {
        coefficients.push_back(generate_random_zq());
    }
    return coefficients;
}

BIGNUM *DistributedSigner::evaluate_polynomial(const std::vector<BIGNUM *> &coefficients, int x)
{ //offline
    BIGNUM *result = BN_new();  // Final result
    BIGNUM *temp = BN_new();    // Temporary variable for intermediate computations
    BIGNUM *x_power = BN_new(); // Holds x^i

    BN_zero(result); // Initialize result to 0
    BN_one(x_power); // x^0 = 1

    for (size_t i = 0; i < coefficients.size(); i++)
    {
        // temp = coefficients[i] * x_power mod order
        BN_mod_mul(temp, coefficients[i], x_power, order, ctx);

        // result = result + temp mod order
        BN_mod_add(result, result, temp, order, ctx);

        // x_power = x_power * x mod order
        BN_mul_word(x_power, x); // x_power *= x
    }

    BN_free(temp);
    BN_free(x_power);

    return result;
}

DistributedSigner:: DistributedSigner(int threshold, int total_participants)
    : t(threshold), n(total_participants)
{ //offline
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    order = BN_new();
    EC_GROUP_get_order(group, order, nullptr);
    publicKey = EC_POINT_new(group);

    EC_POINT_set_to_infinity(group, publicKey);
    generator = EC_POINT_new(group);
    EC_POINT_copy(generator, EC_GROUP_get0_generator(group));
    ctx = BN_CTX_new();

    for (int i = 1; i <= total_participants; i++)
    {
        Participant* participant = new Participant();
        participant->participant_id = i;
        participants.push_back(participant);
    }

}

void DistributedSigner:: generateKeys(EC_POINT* pubKey, BIGNUM *privateKey){ // TOD O: should be offline phase
    //BIGNUM *privateKey = generate_random_zq();
    //EC_POINT_mul(group, publicKey, privateKey, nullptr, nullptr, ctx);
    EC_POINT_copy(publicKey, pubKey);
    std::vector<BIGNUM *> polynomial = generate_polynomial_t(privateKey);


    for (int i = 0; i < n; i++){
        participants[i]->x = evaluate_polynomial(polynomial, i + 1);
    }

    for (auto coeff : polynomial)
        BN_free(coeff);
}

Signature* DistributedSigner:: signMessage(BIGNUM* msgHash, const std::vector<int> &signingGroup)
{
    Signature* sig = new Signature();

    for(int i : signingGroup){
        participants[i]->k = generate_random_zq();
        participants[i]->y = generate_random_zq();
    }

    BIGNUM* ky = BN_new();
    BN_zero(ky);

    BIGNUM* w = BN_new();
    for (int i : signingGroup) {
        BN_zero(w);

        for (int j : signingGroup) {
            BIGNUM* term = BN_new();
            BN_mod_mul(term, participants[i]->k, participants[j]->y, order, ctx);
            BN_mod_add(w, w, term, order, ctx);
            BN_free(term);
        }

        // Summing up the contributions
        BN_mod_add(ky, ky, w, order, ctx);
    }
    BN_free(w);

    BIGNUM* delta_inv = BN_new();

    // Compute ky^-1 mod q using OpenSSL's BN_mod_inverse
    if (!BN_mod_inverse(delta_inv, ky, order, ctx)) {
        std::cerr << "Error computing modular inverse!" << std::endl;
        BN_free(delta_inv);
        return nullptr;
    }

    EC_POINT* R = computeR(signingGroup, delta_inv);
    BN_free(delta_inv);

    sig->r = H0(R);
    EC_POINT_free(R);

    // Compute sigma = ki * lambda_i*xi
    compute_sigma(signingGroup);

    sig->s = BN_new();
    BN_zero(sig->s);

    // partialSignature
    for (int i : signingGroup) {
        BIGNUM* temp = BN_new();
        BN_mod_mul(temp, sig->r, participants[i]->sigma, order, ctx);
        BN_mod_mul(participants[i]->s, participants[i]->k, msgHash, order, ctx);
        BN_mod_add(participants[i]->s, participants[i]->s, temp, order, ctx);
        BN_mod_add(sig->s, sig->s, participants[i]->s, order, ctx);
        BN_free(temp);
    }

    BIGNUM* half_order = BN_new();
    BN_rshift1(half_order, order); // half_order = order / 2

    if (BN_cmp(sig->s, half_order) > 0) {
        BN_sub(sig->s, order, sig->s); // sig->s = order - sig->s
    }
    BN_free(half_order);

    return sig;
}


void DistributedSigner:: compute_sigma(std::vector<int> signingGroup) {
    BIGNUM *num = BN_new();  // Numerator (j + 1)
    BIGNUM *den = BN_new();  // Denominator (j - i)
    BIGNUM *inv = BN_new();  // Inverse of denominator
    BIGNUM *temp = BN_new();
    BIGNUM* wi = BN_new();

    for (int i : signingGroup) {
        for (int j : signingGroup) {
            if (j != i) {
                // num = (j + 1)
                BN_set_word(num, j + 1);

                // den = (j - i)
                BN_set_word(den, std::abs(j - i));
                if (j - i < 0) {
                    BN_set_negative(den, 1);
                }

                // Compute modular inverse of den mod q: inv = den^(-1) mod q
                BN_mod_inverse(inv, den, order, ctx); //TOD O: check

                // Compute multiplication: gamma[i] *= (num * inv) mod q
                BN_mod_mul(temp, num, inv, order, ctx);
                BN_mod_mul(participants[i]->gamma, participants[i]->gamma, temp, order, ctx);
            }
        }
        BN_mod_mul(participants[i]->w, participants[i]->gamma, participants[i]->x,order, ctx);

    }

    BIGNUM* tempKW = BN_new();

    for (int i : signingGroup) {
        for (int j : signingGroup) {

            BN_mod_mul(tempKW, participants[j]->k, participants[i]->w, order, ctx);
            BN_mod_add(participants[i]->sigma, participants[i]->sigma, tempKW, order, ctx);
        }
    }

    // Free memory
    BN_free(tempKW);
    BN_free(num);
    BN_free(den);
    BN_free(inv);
    BN_free(temp);
    BN_free(wi);

}



// Function to compute R in a distributed way
EC_POINT* DistributedSigner:: computeR(const std::vector<int> &signingGroup, BIGNUM* delta_inv) {
    EC_POINT* R = EC_POINT_new(group);
    EC_POINT_set_to_infinity(group, R); // Start with neutral element

    for (auto i : signingGroup) {
        EC_POINT* Ri = EC_POINT_new(group);

        // Compute Ri = g^(γi * δ^-1)
        BIGNUM* exp = BN_new();
        BN_mod_mul(exp, participants[i]->y, delta_inv, order, ctx);
        EC_POINT_mul(group, Ri, exp, NULL, NULL, ctx);

        // Add Ri to the total R
        EC_POINT_add(group, R, R, Ri, ctx);

        // Cleanup
        BN_free(exp);
        EC_POINT_free(Ri);
    }

    return R; // Final aggregated R = ∑ g^(γi * δ^-1)
}


bool DistributedSigner:: verifySignature(BIGNUM * msgHash, Signature* signature){
    BIGNUM * s_inv = BN_new();
    if (!BN_mod_inverse(s_inv, signature->s, order, ctx)) {
        std::cerr << "Error computing modular inverse!" << std::endl;
        BN_free(s_inv);
        return false;
    }

    BIGNUM* exp = BN_new();
    EC_POINT* R0 = EC_POINT_new(group);
    EC_POINT* R1 = EC_POINT_new(group);



    BN_mod_mul(exp, msgHash, s_inv, order, ctx);
    EC_POINT_mul(group, R0, exp, NULL, NULL, ctx);
    BN_mod_mul(exp, signature->r, s_inv, order, ctx);
    EC_POINT_mul(group, R1, NULL, publicKey, exp, ctx);
    EC_POINT_add(group, R0, R0, R1, ctx); // TOD O: is it add?

    BN_free(s_inv);
    BN_free(exp);
    EC_POINT_free(R1);

    BIGNUM* r = H0(R0);
    EC_POINT_free(R0);

    bool res = BN_cmp(r, signature->r) == 0;
    BN_free(r);
    return res;

}
