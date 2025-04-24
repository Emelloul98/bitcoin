#include "simpleECDSA.hpp"
/*
 *  simpleECDSA class constructor
*/
simpleECDSA:: simpleECDSA(int threshold, int total_participants)
        : t(threshold), n(total_participants)
{
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    order = BN_new();
    EC_GROUP_get_order(group, order, nullptr);
    std::cout << "order: " << BN_bn2hex(order) << std::endl;
    publicKey = EC_POINT_new(group);

    EC_POINT_set_to_infinity(group, publicKey);
    generator = EC_POINT_new(group);
    EC_POINT_copy(generator, EC_GROUP_get0_generator(group));
    ctx = BN_CTX_new();
    char* gen_str = EC_POINT_point2hex(group, generator, POINT_CONVERSION_UNCOMPRESSED, ctx);//prints
    std::cout << "Generator point G: " << gen_str << std::endl; // prints
    OPENSSL_free(gen_str);//prints
    for (int i = 0; i < total_participants; i++) {
        std::string filename = "participant_" + std::to_string(i+1) + ".dat";
        std::ofstream outfile(filename);
        if (outfile.is_open()) {
            outfile << "# Secret data for participant" << (i) << "\n";
            outfile.close();
            std::cout << "Created file: " << filename << std::endl;
        } else {
            std::cerr << "Error: could not create file " << filename << std::endl;
        }
    }
}
/*
 *  generateKeys function:
 *  1.Creates a random private key.
 *  2.Creates a public key relative to the private key.
 *  3.creates a shamir polynomial that the private key is his secret in f(0).
 *  4.saves the f(i) result in a file.
 */
void simpleECDSA::generateKeys()
{
    // Private key creation:
    BIGNUM *privateKey = generate_random_zq();
    std::cout << "private-x: " << BN_bn2hex(privateKey) << std::endl; //prints
    // Public key calculation:
    EC_POINT_mul(group, publicKey, privateKey, nullptr, nullptr, ctx);
    char* pubkey_hex = EC_POINT_point2hex(group, publicKey, POINT_CONVERSION_UNCOMPRESSED, ctx);//prints
    std::cout << "Public key: " << pubkey_hex << std::endl;//prints
    OPENSSL_free(pubkey_hex);//prints
    // shamir polynomial creation:
    std::vector<BIGNUM *> polynomial = generate_polynomial_t(privateKey);
    // save f(i) in participant_i file:
    for (int i = 0; i < n; i++){
        // calculate f(i)
        BIGNUM* secret = evaluate_polynomial(polynomial, i + 1);
        // convert f(i) to bigNum
        char* secret_hex = BN_bn2hex(secret);
        std::string filename = "participant_" + std::to_string(i + 1) + ".dat";
        std::ofstream outfile(filename);
        if (outfile.is_open())
        {
            outfile << "polynomial_secret: " << secret_hex << "\n";
            outfile.close();
            std::cout << "Polynomial secret for participant " << (i + 1)
                      << " saved to " << filename << std::endl;
        } else {
            std::cerr << "Error: cannot open file " << filename << " for writing.\n";
        }
        OPENSSL_free(secret_hex);
        BN_free(secret);
    }
    // free data:
    for (auto coeff : polynomial)
        BN_free(coeff);
    BN_free(privateKey);
}

/*
 * generate_random_zq function:
 * 1.Returns a random integer in the range [1,q-1].
*/
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

/*
 * generate_polynomial_t function:
 * 1.Gets a secret x
 * 2.Generate a random polynomial of degree t-1 over the field Zq
 * 3.returns the polynomial coefficients.
*/
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
