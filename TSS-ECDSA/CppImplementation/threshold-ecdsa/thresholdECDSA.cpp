#include "ThresholdECDSA.hpp"


BIGNUM *ThresholdECDSA::generate_random_zq()
{
    BIGNUM *res = BN_new();
    BN_rand_range(res, order);
    return res;
}


std::vector<BIGNUM *> ThresholdECDSA::generate_polynomial_t(BIGNUM *ui)
{
    std::vector<BIGNUM *> coefficients;
    coefficients.push_back(BN_dup(ui));
    for (int i = 1; i < t; i++)
    {
        coefficients.push_back(generate_random_zq());
    }
    return coefficients;
}

BIGNUM *ThresholdECDSA::evaluate_polynomial(const std::vector<BIGNUM *> &coefficients, int x)
{
    BIGNUM *result = BN_new();  
    BIGNUM *temp = BN_new();    
    BIGNUM *x_power = BN_new(); 
    BN_CTX *ctx = BN_CTX_new(); 

    BN_zero(result); 
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
    BN_CTX_free(ctx);

    return result;
}

ThresholdECDSA:: ThresholdECDSA(int threshold, int total_participants)
    : t(threshold), n(total_participants)
{
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    order = BN_new();
    EC_GROUP_get_order(group, order, nullptr);
    publicKey = EC_POINT_new(group);
    
   
    //if (!EC_POINT_copy(publicKey, EC_GROUP_get0_generator(group))) {
    //    std:: cout << "ctxv";
    //}

    EC_POINT_set_to_infinity(group, publicKey);
    generator = EC_POINT_new(group);
    EC_POINT_copy(generator, EC_GROUP_get0_generator(group));

    for (int i = 1; i <= n; i++)
    {
        Participant* data = new Participant();
        generate_participant_data(i, *data);
        participants.push_back(data);
    }
}
void ThresholdECDSA:: generate_participant_data(int participant_id, Participant &participant)
{
    BN_CTX *ctx = BN_CTX_new();
    participant.participant_id = participant_id;
    BN_rand_range(participant.k, order);
    BN_rand_range(participant.gamma, order);
    BN_rand_range(participant.u, order);

    std::vector<BIGNUM *> polynomial = generate_polynomial_t(participant.u);

    participant.y = EC_POINT_new(group);
    EC_POINT_mul(group, participant.y, participant.u, nullptr, nullptr, ctx);

    for (int i = 1; i <= n; i++)
    {
        BIGNUM *share = evaluate_polynomial(polynomial, i);
        participant.shares.push_back(share);
    }

    for (auto coeff : polynomial)
        BN_free(coeff);
    BN_CTX_free(ctx);
}
void ThresholdECDSA:: generateSignatureShares(const std::vector<int> &signingGroup)
{
    BN_CTX *ctx = BN_CTX_new();

    for (int i = 0; i < n; i++)
    {

        double result = 1.0;

        for (int j : signingGroup)
        {
            if (j == i)
                continue;

            // Calculate j/(j-i)
            result *= static_cast<double>(j) / (j - i);
        }
        std::string wj_str = std::to_string(result); // Convert double to string
        BN_dec2bn(&participants[i]->w, wj_str.c_str());
    }
    // Initialize matrices for storing αij, βij, μij, νij
    json alpha_matrix; // For storing αij values
    json beta_matrix;  // For storing βij values
    json mu_matrix;    // For storing μij values
    json nu_matrix;    // For storing νij values

    // Phase 2 : Calculate αij and βij, Calculate μij and νij
    for (int i : signingGroup)
    {
        for (int j : signingGroup)
        {
            if (i >= j)
                continue; // Process only upper triangle

            // Calculate ki * γj
            BIGNUM *ki_γj = BN_new();
            BN_mul(ki_γj, participants[i]->k, participants[j]->gamma, ctx);

            // Calculate ki * wj
            BIGNUM *ki_wj = BN_new();
            BN_mul(ki_wj, participants[i]->k, participants[j]->w, ctx);

            // Generate random αij
            BIGNUM *alpha_ij = generate_random_zq();
            // Generate random μij
            BIGNUM *mu_ij = generate_random_zq();

            // Calculate βij = ki * γj - αij
            BIGNUM *beta_ij = BN_new();
            BN_sub(beta_ij, ki_γj, alpha_ij);

            // Calculate νij = ki * wj - μij
            BIGNUM *nu_ij = BN_new();
            BN_sub(nu_ij, ki_wj, mu_ij);

            // Store results in matrices
            alpha_matrix[std::to_string(i)][std::to_string(j)] = BN_bn2hex(alpha_ij);
            beta_matrix[std::to_string(i)][std::to_string(j)] = BN_bn2hex(beta_ij);
            alpha_matrix[std::to_string(j)][std::to_string(i)] = BN_bn2hex(beta_ij); // βji = αij
            beta_matrix[std::to_string(j)][std::to_string(i)] = BN_bn2hex(alpha_ij); // αji = βij

            // Store results in matrices
            mu_matrix[std::to_string(i)][std::to_string(j)] = BN_bn2hex(mu_ij);
            nu_matrix[std::to_string(i)][std::to_string(j)] = BN_bn2hex(nu_ij);
            mu_matrix[std::to_string(j)][std::to_string(i)] = BN_bn2hex(nu_ij); // νji = μij
            nu_matrix[std::to_string(j)][std::to_string(i)] = BN_bn2hex(mu_ij); // μji = νij

            BN_free(ki_γj);
            BN_free(alpha_ij);
            BN_free(beta_ij);

            BN_free(ki_wj);
            BN_free(mu_ij);
            BN_free(nu_ij);
        }
    }

    // Calculate final δi and σi for each participant
    for (int i : signingGroup)
    {
        
        BN_zero(participants[i]->delta);
        BN_zero(participants[i]->sigma);


        BIGNUM *ki_gammai = BN_new();
        BN_mul(ki_gammai, participants[i]->k, participants[i]->gamma, ctx);
        BN_add(participants[i]->delta, participants[i]->delta, ki_gammai);
        BN_free(ki_gammai);

        // Add ki * wi to sigma_i
        BIGNUM *ki_wi = BN_new();
        BN_mul(ki_wi, participants[i]->k, participants[i]->w, ctx);
        BN_add(participants[i]->sigma, participants[i]->sigma, ki_wi);
        BN_free(ki_wi);

        // Add all αij and βji to delta_i
        for (int j : signingGroup)
        {
            if (j == i)
                continue;

            BIGNUM *alpha_ij = BN_new();
            BN_hex2bn(&alpha_ij, alpha_matrix[std::to_string(i)][std::to_string(j)].get<std::string>().c_str());
            BIGNUM *beta_ji = BN_new();
            BN_hex2bn(&beta_ji, beta_matrix[std::to_string(j)][std::to_string(i)].get<std::string>().c_str());
            BN_add(participants[i]->delta, participants[i]->delta, alpha_ij);
            BN_add(participants[i]->delta, participants[i]->delta, beta_ji);

            BIGNUM *mu_ij = BN_new();
            BIGNUM *nu_ji = BN_new();
            BN_hex2bn(&mu_ij, mu_matrix[std::to_string(i)][std::to_string(j)].get<std::string>().c_str());
            BN_hex2bn(&nu_ji, nu_matrix[std::to_string(j)][std::to_string(i)].get<std::string>().c_str());

            BN_add(participants[i]->sigma, participants[i]->sigma, mu_ij);
            BN_add(participants[i]->sigma, participants[i]->sigma, nu_ji);

            BN_free(alpha_ij);
            BN_free(beta_ji);
            BN_free(mu_ij);
            BN_free(nu_ji);
        }
        
        
    }

    BN_CTX_free(ctx);
}


ECDSA_SIG* ThresholdECDSA:: combineSignatureShares(const std::vector<int> &signingGroup, const BIGNUM *messageHash)
{

    ECDSA_SIG* finalSig = ECDSA_SIG_new();
    BIGNUM *s = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *K = BN_new();

    for (int i : signingGroup)
    {
        BN_add(K, K, participants[i]->k); // Add the value of ki to K
    }

    BIGNUM *k_inv = BN_new();
    BN_mod_inverse(k_inv, K, order, ctx);
    
    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_mul(group, R, nullptr, generator, k_inv, ctx);

    BN_free(k_inv);
    // Now `R` contains the result point.


    BIGNUM *Rx = BN_new(); // x-coordinate of R
    BIGNUM *r = BN_new();

    // Extract x-coordinate of the point R
    EC_POINT_get_affine_coordinates(group, R, Rx, nullptr, ctx);

    // Compute H0(R) = Rx mod q
    BN_mod(r, Rx, order, ctx);

    for (int i : signingGroup)
    {

        // si = mki + rσi
        BN_mod_mul(participants[i]->s, messageHash, participants[i]->k, order, ctx); // Perform modular multiplication

        // temp = rσi
        BIGNUM *temp = BN_new();
        BN_mod_mul(temp, r, participants[i]->sigma, order, ctx);
        // si = si + temp
        BN_mod_add(participants[i]->s, participants[i]->s, temp, order, ctx);
        BN_free(temp);
    }

    // s = Σsi mod q
    for (int i : signingGroup){
        BN_mod_add(s, s, participants[i]->s, order, ctx); // Perform modular addition
    }

    ECDSA_SIG_set0(finalSig, r, s);

    // Clean up and return result
    BN_free(Rx);
    BN_CTX_free(ctx);

    return finalSig;
}

EC_POINT* ThresholdECDSA:: generateKeys()
{
    BN_CTX *ctx = BN_CTX_new();

    for (int i = 0; i < n; i++)
    {
        BN_zero(participants[i]->x);

        for (int j = 0; j < n; j++)
        {
            BN_mod_add(participants[i]->x, participants[i]->x, participants[j]->shares[i], order, ctx);
        }

    }

    for (int i = 0; i < n; i++)
    {
        // publicKey += yi

        if (!EC_POINT_add(group, publicKey, publicKey, participants[i]->y, ctx))
        {
            ERR_print_errors_fp(stderr);
            std::cout << "Error adding points on elliptic curve" << std::endl;
            continue;
        }

    }

    BN_CTX_free(ctx);
    return publicKey;
}

ECDSA_SIG* ThresholdECDSA:: signMessage(const char *message,size_t message_length, const std::vector<int> &signingGroup, BIGNUM* msgHash)
{
    //msgHash = hash_message(message);
    //unsigned char hash[SHA256_DIGEST_LENGTH];
    //SHA256((unsigned char*)message, message_length, hash);
    //msgHash = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);

    generateSignatureShares(signingGroup);

    ECDSA_SIG* finalSig = combineSignatureShares(signingGroup, msgHash);

    BN_free(msgHash);
    return finalSig;
}

void ThresholdECDSA:: saveToFile(const std::string &filename)
{
    //std::ofstream output_file(filename); // TODO to check if create new file
    //output_file << participants;
    //output_file.close();
}

ThresholdECDSA:: ~ThresholdECDSA()
{
    BN_free(order);
    EC_POINT_free(generator);
    EC_GROUP_free((EC_GROUP *)group);
}

int main()
{
    ThresholdECDSA ecdsa(2, 3);

    EC_POINT * publicKey = ecdsa.generateKeys();
    
    std::vector<int> signingGroup = {0, 1};
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    // Hash the message
    const char *message = "hello world from threshold ecdsa";
    size_t message_length = strlen(message);
    std::cout << "Message: " << message << std::endl;


    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, message_length, hash);
    BIGNUM *msgHash = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);

    // Sign message
    ECDSA_SIG *signature = ecdsa.signMessage(message, message_length, signingGroup, msgHash);

    // Convert EC_POINT to bytes for EVP
    size_t publicKey_len;
    unsigned char *publicKey_bytes = NULL;
    publicKey_len = EC_POINT_point2buf(group, publicKey, POINT_CONVERSION_UNCOMPRESSED, &publicKey_bytes, NULL);


    // Create EVP_PKEY context
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_secp256k1);
    EVP_PKEY_set1_encoded_public_key(pkey, publicKey_bytes, publicKey_len);

    // Convert signature to DER
    unsigned char *sig_der = NULL;
    int sig_der_len = i2d_ECDSA_SIG(signature, &sig_der);

    // Verify signature
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_verify_init(ctx);
    int verify_status = EVP_PKEY_verify(ctx, sig_der, sig_der_len, hash, SHA256_DIGEST_LENGTH);

    std::cout << "Verification status: " << (verify_status == 1 ? "Success" : "Failed") << std::endl;

    // Cleanup
    EC_GROUP_free(group);
    OPENSSL_free(sig_der);
    OPENSSL_free(publicKey_bytes);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey);
    //BN_free(msgHash);
    ECDSA_SIG_free(signature);
    EC_POINT_free(publicKey);

    return 0;
}
