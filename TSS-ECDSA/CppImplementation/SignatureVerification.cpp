#include <iostream>
#include <vector>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h> 

using json = nlohmann::json;

BIGNUM* hash_message(const std::string& message) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, message.c_str(), message.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);

    BIGNUM* bnHash = BN_new();
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

    BIGNUM *generate_random_zq()
    {
        BIGNUM *rand = BN_new();
        BN_rand_range(rand, order);
        return rand;
    }

    std::vector<BIGNUM *> generate_polynomial(BIGNUM *ui, int degree)
    {
        std::vector<BIGNUM *> coefficients;
        coefficients.push_back(BN_dup(ui));
        for (int i = 1; i < degree; i++)
        {
            coefficients.push_back(generate_random_zq());
        }
        return coefficients;
    }

    BIGNUM *evaluate_polynomial(const std::vector<BIGNUM *> &coefficients, int x)
    {
        BIGNUM *result = BN_new();  // התוצאה הסופית
        BIGNUM *temp = BN_new();    // משתנה זמני לחישוב
        BIGNUM *x_power = BN_new(); // מחזיק את x^i
        BN_CTX *ctx = BN_CTX_new(); // הקשר לחישובים

        BN_zero(result); // לאתחל את התוצאה ל-0
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

        // שחרור זיכרון
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

    json generate_participant_data(int participant_id)
    {
        json data;
        BN_CTX *ctx = BN_CTX_new();

        BIGNUM *ui = generate_random_zq();
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

        std::vector<std::string> shares;
        for (int i = 1; i <= n; i++)
        {
            BIGNUM *share = evaluate_polynomial(polynomial, i);
            shares.push_back(BN_bn2hex(share));
            BN_free(share);
        }
        data["shares"] = shares;

        EC_POINT_free(yi);
        for (auto coeff : polynomial)
            BN_free(coeff);
        BN_free(ui);
        BN_CTX_free(ctx);

        return data;
    }

    json combine_shares(std::vector<json> &participants_data)
    {
        json result;
        BN_CTX *ctx = BN_CTX_new();

        for (int i = 0; i < n; i++)
        {
            BIGNUM *xi = BN_new();
            BN_zero(xi);

            for (const auto &data : participants_data)
            {
                BIGNUM *share = BN_new();
                BN_hex2bn(&share, data["shares"][i].get<std::string>().c_str());
                BN_mod_add(xi, xi, share, order, ctx);
                BN_free(share);
            }

            participants_data[i]["xi"] = BN_bn2hex(xi);
        }

        EC_POINT *Y = EC_POINT_new(group);
        EC_POINT_set_to_infinity(group, Y);
        EC_POINT *temp = EC_POINT_new(group); 

        for (const auto &participant : participants_data)
        {
            const std::string &yi_hex = participant["yi"];
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
