#include <iostream>
#include <vector>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h> 

using json = nlohmann::json;

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
