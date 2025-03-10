#include <iostream>
#include <vector>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <fstream>


using json = nlohmann::json;

struct Participant {
    BIGNUM* ui;
    BIGNUM* ki;
    BIGNUM* wi;
    BIGNUM* xi;

    BIGNUM* gamma_i;
    BIGNUM* sigma_i;
    BIGNUM* delta_i;
    BIGNUM* s_i;
    EC_POINT* yi;
    std::vector<BIGNUM*> polynomial;
    std::vector<BIGNUM*> shares;
    int participant_id;
}

 BIGNUM *generate_random_zq(BIGNUM *order)
    {
        BIGNUM *rand = BN_new();
        BN_rand_range(rand, order);
        return rand;
    }

BIGNUM *hash_message(const std::string &message)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, message.c_str(), message.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);

    BIGNUM *bnHash = BN_new();
    BN_bin2bn(hash, hash_len, bnHash);

    EVP_MD_CTX_free(ctx);
    return bnHash;
}

class SignatureVerification
{
private:
    const EC_GROUP *group;
    BIGNUM *order;
    EC_POINT *publicKey;

public:
    SignatureVerification(const std::string &pubKeyHex)
    {
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        order = BN_new();
        EC_GROUP_get_order(group, order, nullptr);

        BN_CTX *ctx = BN_CTX_new();
        publicKey = EC_POINT_new(group);

        std::cout << "Initializing verification with public key: " << pubKeyHex << std::endl;

        if (!EC_POINT_hex2point(group, pubKeyHex.c_str(), publicKey, ctx))
        {
            std::cerr << "Failed to decode public key" << std::endl;
            throw std::runtime_error("Invalid public key format");
        }

        if (!EC_POINT_is_on_curve(group, publicKey, ctx))
        {
            std::cerr << "Public key point is not on curve" << std::endl;
            throw std::runtime_error("Invalid public key point");
        }

        BN_CTX_free(ctx);
    }

    bool verifySignature(const std::string &messageHex, const json &signature)
    {
        BN_CTX *ctx = BN_CTX_new();
        bool isValid = false;

        try
        {
            std::cout << "Verifying signature with:" << std::endl;
            std::cout << "r: " << signature["r"].get<std::string>() << std::endl;
            std::cout << "s: " << signature["s"].get<std::string>() << std::endl;

            BIGNUM *e = hash_message(messageHex);
            std::cout << "Verification hash: " << BN_bn2hex(e) << std::endl;

            // Extract r and s from signature
            BIGNUM *r = BN_new();
            BIGNUM *s = BN_new();
            BN_hex2bn(&r, signature["r"].get<std::string>().c_str());
            BN_hex2bn(&s, signature["s"].get<std::string>().c_str());

            // Verify that r and s are in [1, n-1]
            if (BN_is_zero(r) || BN_is_zero(s) ||
                BN_cmp(r, order) >= 0 || BN_cmp(s, order) >= 0)
            {
                throw std::runtime_error("Invalid signature values");
            }

            // Calculate w = s^(-1) mod n
            BIGNUM *w = BN_new();
            BN_mod_inverse(w, s, order, ctx);

            // Calculate u1 = ew mod n
            BIGNUM *u1 = BN_new();
            BN_mod_mul(u1, e, w, order, ctx);

            // Calculate u2 = rw mod n
            BIGNUM *u2 = BN_new();
            BN_mod_mul(u2, r, w, order, ctx);

            // Calculate point (x,y) = u1*G + u2*publicKey
            EC_POINT *point = EC_POINT_new(group);
            EC_POINT *temp1 = EC_POINT_new(group);
            EC_POINT *temp2 = EC_POINT_new(group);

            // u1*G
            EC_POINT_mul(group, temp1, u1, nullptr, nullptr, ctx);
            // u2*publicKey
            EC_POINT_mul(group, temp2, nullptr, publicKey, u2, ctx);
            // Add points
            EC_POINT_add(group, point, temp1, temp2, ctx);

            // Get x coordinate
            BIGNUM *x = BN_new();
            EC_POINT_get_affine_coordinates(group, point, x, nullptr, ctx);

            // Calculate v = x mod n
            BIGNUM *v = BN_new();
            BN_mod(v, x, order, ctx);

            // Verify v == r
            isValid = (BN_cmp(v, r) == 0);

            // Cleanup
            BN_free(e);
            BN_free(r);
            BN_free(s);
            BN_free(w);
            BN_free(u1);
            BN_free(u2);
            BN_free(x);
            BN_free(v);
            EC_POINT_free(point);
            EC_POINT_free(temp1);
            EC_POINT_free(temp2);
        }
        catch (const std::exception &e)
        {
            BN_CTX_free(ctx);
            throw;
        }

        BN_CTX_free(ctx);
        return isValid;
    }
};


class ThresholdKeyGen
{
private:
    const EC_GROUP *group;
    BIGNUM *order;
    EC_POINT *generator;
    int t;
    int n;

   
    std::vector<BIGNUM *> generate_polynomial(BIGNUM *ui, int degree)
    {
        std::vector<BIGNUM *> coefficients;
        coefficients.push_back(BN_dup(ui));
        for (int i = 1; i < degree; i++)
        {
            coefficients.push_back(generate_random_zq(order));
        }
        return coefficients;
    }

    BIGNUM *evaluate_polynomial(const std::vector<BIGNUM *> &coefficients, int x)
    {
        BIGNUM *result = BN_new();
        BIGNUM *temp = BN_new();  
        BIGNUM *x_power = BN_new();
        BN_CTX *ctx = BN_CTX_new();

        BN_zero(result);
        BN_one(x_power);

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

public:
    ThresholdKeyGen(int threshold, int total_participants)
        : t(threshold), n(total_participants)
    {
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        order = BN_new();
        generator = EC_POINT_new(group);
        EC_POINT_copy(generator, EC_GROUP_get0_generator(group));
        EC_GROUP_get_order(group, order, nullptr);
    }

    ~ThresholdKeyGen()
    {
        BN_free(order);
        EC_POINT_free(generator);
        EC_GROUP_free((EC_GROUP *)group);
    }

    void generate_participant_data(int participant_id, json &data)
    {
        BN_CTX *ctx = BN_CTX_new();

        BIGNUM *ui = generate_random_zq(order);
        std::vector<BIGNUM *> polynomial = generate_polynomial(ui, t);

        std::vector<std::string> poly_str;
        for (auto coeff : polynomial)
        {
            poly_str.push_back(BN_bn2hex(coeff));
        }

        EC_POINT *yi = EC_POINT_new(group);
        EC_POINT_mul(group, yi, ui, nullptr, nullptr, ctx);

        data["yi"] = EC_POINT_point2hex(group, yi, POINT_CONVERSION_COMPRESSED, ctx);
        data["participant_id"] = participant_id;
        data["ui"] = BN_bn2hex(ui);
        data["polynomial"] = poly_str;
        data["g"] = EC_POINT_point2hex(group, generator, POINT_CONVERSION_COMPRESSED, ctx);
        data["q"] = BN_bn2hex(order);

        for (int i = 1; i <= n; i++)
        {
            BIGNUM *share = evaluate_polynomial(polynomial, i);
            data["shares"].push_back(BN_bn2hex(share));
            BN_free(share);
        }

        EC_POINT_free(yi);
        for (auto coeff : polynomial)
            BN_free(coeff);
        BN_free(ui);
        BN_CTX_free(ctx);

    }

    json combine_shares(json &participants_data)
    {
        json result;
        BN_CTX *ctx = BN_CTX_new();

        for (int i = 0; i < n; i++)
        {
            BIGNUM *xi = BN_new();
            BN_zero(xi);

            for (int j = 0; j < n; j++)
            {
                BIGNUM *share = BN_new();
                BN_hex2bn(&share, participants_data[j]["shares"][i].get<std::string>().c_str());
                BN_mod_add(xi, xi, share, order, ctx);
                BN_free(share);
            }

            participants_data[i]["xi"] = BN_bn2hex(xi);
        }

        EC_POINT *Y = EC_POINT_new(group);
        EC_POINT_set_to_infinity(group, Y);
        EC_POINT *temp = EC_POINT_new(group); 

        for (int i = 0; i < n; i++)
        {
            const std::string &yi_hex = participants_data[i]["yi"];
            if (!EC_POINT_hex2point(group, yi_hex.c_str(), temp, ctx))
            {
                std::cerr << "Error decoding EC_POINT from hex: " << yi_hex << std::endl;
                continue;
            }

            // Y = Y + yi
            if (!EC_POINT_add(group, Y, Y, temp, ctx))
            {
                std::cerr << "Error adding points on elliptic curve" << std::endl;
                continue;
            }
        }

        result["public_key"] = EC_POINT_point2hex(group, Y, POINT_CONVERSION_UNCOMPRESSED, ctx);

        EC_POINT_free(Y);
        BN_CTX_free(ctx);
        EC_POINT_free(temp);
        return result;
    }
};

class ThresholdSigning 
{
private:
    const EC_GROUP *group;
    BIGNUM *order;
    int t;
    int n;

    
public:
    ThresholdSigning(int threshold, int total_participants)
        : t(threshold), n(total_participants)
    {
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        order = BN_new();
        EC_GROUP_get_order(group, order, nullptr);
    }

    ~ThresholdSigning()
    {
        BN_free(order);
        EC_GROUP_free((EC_GROUP *)group);
    }

    void generateSignatureShares(json &participants_data, const std::vector<int> &signingGroup)
    {
        BN_CTX *ctx = BN_CTX_new();

        for (int i = 0; i < n; i++)
        {
            participants_data[i]["ki"] = BN_bn2hex(generate_random_zq(order));
            participants_data[i]["gammai"] = BN_bn2hex(generate_random_zq(order));

            double result = 1.0;

            for (int j : signingGroup)
            {
                if (j == i)
                    continue;

                // Calculate j/(j-i)
                result *= static_cast<double>(j) / (j - i);
            }
            std::string wj_str = std::to_string(result); // Convert double to string
            BIGNUM *wj_bn = BN_new();
            BN_dec2bn(&wj_bn, wj_str.c_str());
            participants_data[i]["wi"] = BN_bn2hex(wj_bn);
            BN_free(wj_bn); // Free the BIGNUM after use

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

                BIGNUM *ki = BN_new();
                BIGNUM *gammaj = BN_new();
                BIGNUM * wj = BN_new();

                BN_hex2bn(&ki, participants_data[i]["ki"].get<std::string>().c_str());
                BN_hex2bn(&gammaj, participants_data[j]["gammai"].get<std::string>().c_str());
                BN_hex2bn(&wj, participants_data[j]["wi"].get<std::string>().c_str());


                // Calculate ki * γj
                BIGNUM *product = BN_new();
                BN_mul(product, ki, gammaj, ctx);

                // Calculate ki * wj
                BIGNUM *product1 = BN_new();
                
                BN_mul(product1, ki, wj, ctx);

                // Generate random αij
                BIGNUM *alpha_ij = generate_random_zq(order);
                // Generate random μij
                BIGNUM *mu_ij = generate_random_zq(order);

                // Calculate βij = ki * γj - αij
                BIGNUM *beta_ij = BN_new();
                BN_sub(beta_ij, product, alpha_ij);

                // Calculate νij = ki * wj - μij
                BIGNUM *nu_ij = BN_new();
                BN_sub(nu_ij, product1, mu_ij);

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

                BN_free(product);
                BN_free(alpha_ij);
                BN_free(beta_ij);
                BN_free(ki);
                BN_free(gammaj);

                BN_free(product1);
                BN_free(mu_ij);
                BN_free(nu_ij);
                BN_free(wj);
            }
        }

        // Calculate final δi and σi for each participant
        for (int i : signingGroup)
        {
            BIGNUM *delta_i = BN_new();
            BIGNUM *sigma_i = BN_new();
            BN_zero(delta_i);
            BN_zero(sigma_i);

            // Add ki * γi to delta_i
            BIGNUM *ki = BN_new();
            BIGNUM *gammai = BN_new();
            BN_hex2bn(&ki, participants_data[i]["ki"].get<std::string>().c_str());
            BN_hex2bn(&gammai, participants_data[i]["gammai"].get<std::string>().c_str());

            BIGNUM *ki_gammai = BN_new();
            BN_mul(ki_gammai, ki, gammai, ctx);
            BN_add(delta_i, delta_i, ki_gammai);

            // Add ki * wi to sigma_i
            BIGNUM *wi = BN_new();
            BN_hex2bn(&wi, participants_data[i]["wi"].get<std::string>().c_str());
            BIGNUM *ki_wi = BN_new();
            BN_mul(ki_wi, ki, wi, ctx);
            BN_add(sigma_i, sigma_i, ki_wi);

            // Add all αij and βji to delta_i
            for (int j : signingGroup)
            {
                if (j == i)
                    continue;

                BIGNUM *alpha_ij = BN_new();
                BN_hex2bn(&alpha_ij,  alpha_matrix[std::to_string(i)][std::to_string(j)].get<std::string>().c_str());
                BIGNUM *beta_ji = BN_new();
                BN_hex2bn(&beta_ji, beta_matrix[std::to_string(j)][std::to_string(i)].get<std::string>().c_str());
                BN_add(delta_i, delta_i, alpha_ij);
                BN_add(delta_i, delta_i, beta_ji);

                BIGNUM *mu_ij = BN_new();
                BIGNUM *nu_ji = BN_new();
                BN_hex2bn(&mu_ij, mu_matrix[std::to_string(i)][std::to_string(j)].get<std::string>().c_str());
                BN_hex2bn(&nu_ji, nu_matrix[std::to_string(j)][std::to_string(i)].get<std::string>().c_str());

                BN_add(sigma_i, sigma_i, mu_ij);
                BN_add(sigma_i, sigma_i, nu_ji);

                BN_free(alpha_ij);
                BN_free(beta_ji);
                BN_free(mu_ij);
                BN_free(nu_ji);
            }

            // Store results
            participants_data[i]["delta_i"] = BN_bn2hex(delta_i);
            participants_data[i]["sigma_i"] = BN_bn2hex(sigma_i);

            BN_free(delta_i);
            BN_free(sigma_i);
            BN_free(ki);
            BN_free(gammai);
            BN_free(ki_gammai);
            BN_free(wi);
            BN_free(ki_wi);
        }

        BN_CTX_free(ctx);
    }

    // פונקציה לחישוב g^(k^(-1)) mod q
    BIGNUM *compute_g_exp_k_inv_mod_q(const BIGNUM *g, const BIGNUM *k, const BIGNUM *q, BN_CTX *ctx)
    {
        BIGNUM *k_inv = BN_new();  // k^-1
        BIGNUM *result = BN_new(); // התוצאה g^(k^-1) mod q

        if (!BN_mod_inverse(k_inv, k, q, ctx))
        {
            std::cerr << "Error: k is not invertible modulo q" << std::endl;
            BN_free(k_inv);
            BN_free(result);
            return nullptr;
        }

        if (!BN_mod_exp(result, g, k_inv, q, ctx))
        {
            std::cerr << "Error in modular exponentiation" << std::endl;
            BN_free(k_inv);
            BN_free(result);
            return nullptr;
        }

        BN_free(k_inv);
        return result;
    }

    

    json combineSignatureShares(json &participants_data, const std::vector<int> &signingGroup, const BIGNUM *messageHash)
    {
        
        BIGNUM *finalSignature = BN_new();
        BN_CTX *ctx = BN_CTX_new();

        BIGNUM *K = BN_new();
        // BIGNUM *R = BN_new();

        for (int i : signingGroup)
        {
            BIGNUM *ki = BN_new();
            if (!BN_hex2bn(&ki, participants_data[i]["ki"].get<std::string>().c_str())) {
                std::cerr << "Error: Failed to convert ki to BIGNUM" << std::endl;
                BN_free(ki);
                return nullptr; // Handle error appropriately
            }
            BN_add(K, K, ki); // Add the value of ki to K
            BN_free(ki);

        }

        auto generator = EC_POINT_new(group);
        EC_POINT_copy(generator, EC_GROUP_get0_generator(group));

        BIGNUM *k_inv = BN_new();
        if (!BN_mod_inverse(k_inv, K, order, ctx)) {
            std::cerr << "Error: k is not invertible modulo q." << std::endl;
            BN_free(k_inv);
            return nullptr; // Handle error appropriately
        }

        EC_POINT *R = EC_POINT_new(group);
        if (!EC_POINT_mul(group, R, nullptr, generator, k_inv, ctx)) {
            std::cerr << "Error: Failed to compute R = k_inv * generator." << std::endl;
            BN_free(k_inv);
            EC_POINT_free(R);
            return nullptr; // Handle error appropriately
        }

        BN_free(k_inv);
        // Now `R` contains the result point.

        // R = compute_g_exp_k_inv_mod_q(generator, K, order, ctx);
            
        BIGNUM* Rx = BN_new();  // x-coordinate of R
        BIGNUM* r = BN_new();  // Result: H0(R) = Rx mod q

        // Extract x-coordinate of the point R
        if (!EC_POINT_get_affine_coordinates(group, R, Rx, nullptr, ctx)) {
            std::cerr << "Error: Unable to extract x-coordinate of R." << std::endl;
            BN_free(Rx);
            BN_free(r);
            return nullptr;
        }

        // Compute H0(R) = Rx mod q
        if (!BN_mod(r, Rx, order, ctx)) {
            std::cerr << "Error: Modular reduction failed." << std::endl;
            BN_free(Rx);
            BN_free(r);
            return nullptr;
        }

        for (int i : signingGroup)
        {
            BIGNUM *s_i = BN_new();
            BIGNUM *sigma_i = BN_new();
            BN_hex2bn(&sigma_i, participants_data[i]["sigma_i"].get<std::string>().c_str());

            //si = mki + rσi
            std::string ki_str = participants_data[i]["ki"].get<std::string>();
            BIGNUM *ki = BN_new();
            BN_hex2bn(&ki, ki_str.c_str());
          
            BN_mod_mul(s_i, messageHash, ki, order, ctx); // Perform modular multiplication
            BN_free(ki); // Free the temporary BIGNUM

            //temp = rσi
            BIGNUM *temp = BN_new();
            BN_mod_mul(temp, r, sigma_i, order, ctx);
            //si = si + temp
            BN_mod_add(s_i, s_i, temp, order, ctx);
            participants_data[i]["s_i"] = BN_bn2hex(s_i);
            BN_free(s_i);
            BN_free(sigma_i);
            BN_free(temp);

        }

        for (int i : signingGroup)
        {
            // s = Σsi mod q
            std::string s_i_str = participants_data[i]["s_i"].get<std::string>();
            BIGNUM *s_i = BN_new();
            BN_hex2bn(&s_i, s_i_str.c_str());

            BN_mod_add(finalSignature, finalSignature, s_i, order, ctx); // Perform modular addition
            BN_free(s_i); // Free the temporary BIGNUM
        }

        // Clean up and return result
        BN_free(Rx);
        BN_CTX_free(ctx);

        json finalSig;
        finalSig["r"] = BN_bn2hex(r);
        finalSig["s"] = BN_bn2hex(finalSignature);

        return finalSig;
    }
};


class ThresholdECDSA
{
private:
    std::unique_ptr<ThresholdKeyGen> keyGen;
    std::unique_ptr<ThresholdSigning> signing;
    json publicKeyData;
    int t;
    int n;

public:
    json participantsData;
    std:: vector<Participant> participants;

    ThresholdECDSA(int threshold, int total_participants)
        : t(threshold), n(total_participants)
    {
        keyGen = std::make_unique<ThresholdKeyGen>(t, n);
        signing = std::make_unique<ThresholdSigning>(t, n);
    }

    void generateKeys()
    {
        for (int i = 0; i < n; i++)
        {
            json data;
            keyGen->generate_participant_data(i, data);
            participantsData.push_back(data);
        }
        for (const auto& participant : participantsData.items()) {
            std::cout << "Participant " << participant.key() << ":\n"
                      << participant.value().dump(4) << "\n\n";
        }
        publicKeyData = keyGen->combine_shares(participantsData);
        std::cout << "test 7" << "\n";
    }

    json signMessage(const std::string &message, const std::vector<int> &signingGroup)
    {
        BIGNUM *msgHash = hash_message(message);
        std::cout << "Message hash: " << BN_bn2hex(msgHash) << std::endl;

        std::cout << "Using public key: " << publicKeyData["public_key"].get<std::string>() << std::endl;

        signing->generateSignatureShares(participantsData, signingGroup);

        auto finalSig = signing->combineSignatureShares(participantsData, signingGroup, msgHash);

        BN_free(msgHash);
        return finalSig;
    }

    bool verifySignature(const std::string &message, const json &signature)
    {
        SignatureVerification verifier(publicKeyData["public_key"].get<std::string>());
        return verifier.verifySignature(message, signature);
    }

    void saveToFile(const std::string &filename)
    {
        std::ofstream output_file(filename); //TODO to check if create new file
        output_file << participantsData.dump(2);
        output_file.close();
        
    }
};
