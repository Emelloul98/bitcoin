#include <stdio.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>

// Generate an ECDSA private/public key pair
int generate_key_pair(EC_KEY **private_key, EC_KEY **public_key) {
    *private_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (*private_key == NULL) return 0;

    if (EC_KEY_generate_key(*private_key) != 1) {
        EC_KEY_free(*private_key);
        return 0;
    }

    *public_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (*public_key == NULL) return 0;

    const EC_POINT *pub_point = EC_KEY_get0_public_key(*private_key);
    if (EC_KEY_set_public_key(*public_key, pub_point) != 1) {
        EC_KEY_free(*public_key);
        return 0;
    }

    return 1;
}

// Sign the message using the private key share
int sign_message(EC_KEY *private_key, const unsigned char *msg, size_t msg_len, ECDSA_SIG **sig) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(msg, msg_len, md);

    *sig = ECDSA_do_sign(md, SHA256_DIGEST_LENGTH, private_key);
    if (*sig == NULL) {
        return 0;
    }
    return 1;
}

// Verify the ECDSA signature
int verify_signature(EC_KEY *public_key, const unsigned char *msg, size_t msg_len, ECDSA_SIG *sig) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(msg, msg_len, md);

    return ECDSA_do_verify(md, SHA256_DIGEST_LENGTH, sig, public_key);
}

int main() {
    EC_KEY *private_key = NULL;
    EC_KEY *public_key = NULL;
    ECDSA_SIG *sig = NULL;

    // Generate key pair
    if (!generate_key_pair(&private_key, &public_key)) {
        printf("Error generating key pair\n");
        return 1;
    }

    // Example message to sign
    unsigned char msg[] = "Hello, threshold ECDSA!";
    size_t msg_len = strlen((char*)msg);

    // Sign message (participant 1)
    if (!sign_message(private_key, msg, msg_len, &sig)) {
        printf("Error signing message\n");
        return 1;
    }

    // Verify the signature (for demonstration purposes)
    if (verify_signature(public_key, msg, msg_len, sig)) {
        printf("Signature is valid\n");
    } else {
        printf("Signature is invalid\n");
    }

    // Cleanup
    ECDSA_SIG_free(sig);
    EC_KEY_free(private_key);
    EC_KEY_free(public_key);

    return 0;
}

