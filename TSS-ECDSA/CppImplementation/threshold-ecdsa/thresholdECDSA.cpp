#include "simpleECDSA.hpp"


// Hash function H: maps a string to an integer in Zq
BIGNUM* simpleECDSA:: H(const std::string& input) {
    // Compute SHA-256 hash of the input
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

    // Convert hash to a BIGNUM
    BIGNUM* h_bn = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, h_bn);

    // Reduce modulo q to ensure it belongs to Zq
    BIGNUM* result = BN_new();
    BN_mod(result, h_bn, order, ctx);

    // Cleanup
    BN_free(h_bn);

    return result;  // This is H(input) ∈ Zq
}


// Hash function H0: maps an elliptic curve point to an integer in Zq
BIGNUM* simpleECDSA:: H0(const EC_POINT* point) {
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Extract (x, y) coordinates of the elliptic curve point
    EC_POINT_get_affine_coordinates(group, point, x, y, ctx);


    // Convert x-coordinate to binary and hash it
    int x_len = BN_num_bytes(x);
    unsigned char* x_bytes = new unsigned char[x_len];
    BN_bn2bin(x, x_bytes);
    SHA256(x_bytes, x_len, hash);
    
    // Convert hash to BIGNUM and reduce mod q
    BIGNUM* h0_bn = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, h0_bn);
    BIGNUM* result = BN_new();
    BN_mod(result, h0_bn, order, ctx);

    // Cleanup
    delete[] x_bytes;
    BN_free(x);
    BN_free(y);
    BN_free(h0_bn);

    return result;  // This is H0(R) ∈ Zq
}


BIGNUM *simpleECDSA::generate_random_zq()
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
    return res;
}


std::vector<BIGNUM *> simpleECDSA::generate_polynomial_t(BIGNUM *x) 
{
    std::vector<BIGNUM *> coefficients;
    coefficients.push_back(BN_dup(x));
    for (int i = 1; i < t; i++)
    {
        coefficients.push_back(generate_random_zq());
    }
    return coefficients;
}

BIGNUM *simpleECDSA::evaluate_polynomial(const std::vector<BIGNUM *> &coefficients, int x)
{
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

simpleECDSA:: simpleECDSA(int threshold, int total_participants)
    : t(threshold), n(total_participants)
{
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

void simpleECDSA:: generateKeys(){ // TODO: should be offline phase
    BIGNUM *privateKey = generate_random_zq();
    EC_POINT_mul(group, publicKey, privateKey, nullptr, nullptr, ctx);

    std::vector<BIGNUM *> polynomial = generate_polynomial_t(privateKey);

    for (int i = 0; i < n; i++){
        participants[i]->x = evaluate_polynomial(polynomial, i + 1);
    }

    for (auto coeff : polynomial)
        BN_free(coeff);
    BN_free(privateKey);

}

Signature* simpleECDSA:: signMessage(const std::string& message, const std::vector<int> &signingGroup)
{
    BIGNUM * msgHash = H(message);
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

    BN_free(msgHash);
    return sig;
}


void simpleECDSA:: compute_sigma(std::vector<int> signingGroup) {
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
                BN_mod_inverse(inv, den, order, ctx); //TODO: check

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
EC_POINT* simpleECDSA:: computeR(const std::vector<int> &signingGroup, BIGNUM* delta_inv) { 
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


bool simpleECDSA:: verifySignature(const std::string& message, Signature* signature){
    BIGNUM * msgHash = H(message);
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
    EC_POINT_add(group, R0, R0, R1, ctx); // TODO: is it add?

    BN_free(s_inv);
    BN_free(exp);
    BN_free(msgHash);
    EC_POINT_free(R1);

    BIGNUM* r = H0(R0);
    EC_POINT_free(R0);

    bool res = BN_cmp(r, signature->r) == 0;
    BN_free(r);
    return res;

}

int main()
{
    simpleECDSA ecdsa(2, 3);

    ecdsa.generateKeys();
    
    std::vector<int> signingGroup = {0, 1};

    // Hash the message
    const std::string message = "hello world from threshold ecdsa";
    std::cout << "Message: " << message << std::endl;

    Signature* signature = ecdsa.signMessage(message, signingGroup);
    bool res = ecdsa.verifySignature(message, signature);
    if(res){
        std::cout << "Signature is valid" << std::endl;
    }else{
        std::cout << "Signature is invalid" << std::endl;
    }

}
