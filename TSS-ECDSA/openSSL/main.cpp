#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

// Function to save private key shares in files
void save_private_key_shares(const char *file_prefix, const unsigned char *private_key, size_t key_size, int num_shares, int threshold) {
    FILE *file;
    char filename[100];
    
    // Simulate Shamir's Secret Sharing (for simplicity, we'll just write random shares)
    for (int i = 0; i < num_shares; i++) {
        snprintf(filename, sizeof(filename), "%s_share_%d.txt", file_prefix, i + 1);
        file = fopen(filename, "w");
        if (file) {
            fprintf(file, "Share %d: ", i + 1);
            for (size_t j = 0; j < key_size; j++) {
                fprintf(file, "%02X", private_key[j]);
            }
            fprintf(file, "\n");
            fclose(file);
        }
    }
}

// Function to display message before and after verification
void display_message_before_after_verification(const unsigned char *message, size_t message_len, const ECDSA_SIG *signature, EC_KEY *public_key) {
    // Convert message to string for display
    printf("Original message: ");
    for (size_t i = 0; i < message_len; i++) {
        printf("%02X", message[i]);
    }
    printf("\n");

    // Verify the signature with the public key
    int verify_status = ECDSA_do_verify(message, message_len, signature, public_key);
    if (verify_status == 1) {
        printf("Signature verified successfully!\n");
    } else {
        printf("Signature verification failed!\n");
    }
}

int main() {
    // Generate ECDSA key pair (this is part of your original code)
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(key);
    
    // Generate the message to sign
    unsigned char message[] = "Hello, Shamir!";
    size_t message_len = strlen((char *)message);

    // Sign the message with the private key
    unsigned char *sig = NULL;
    unsigned int sig_len;
    if (ECDSA_sign(0, message, message_len, sig, &sig_len, key) != 1) {
        printf("Error signing the message!\n");
        return 1;
    }

    // Create the signature object from the raw signature
    ECDSA_SIG *signature = ECDSA_SIG_new();
    if (!ECDSA_SIG_set0(signature, BN_bin2bn(sig, sig_len, NULL), BN_bin2bn(sig + sig_len / 2, sig_len / 2, NULL))) {
        printf("Error creating signature object!\n");
        return 1;
    }

    // Display the message before verification
    display_message_before_after_verification(message, message_len, signature, key);
    
    // Get the private key as a BIGNUM
    const BIGNUM *private_key_bn = EC_KEY_get0_private_key(key);
    
    // Convert the BIGNUM to an unsigned char array
    size_t private_key_size = BN_num_bytes(private_key_bn);
    unsigned char private_key[private_key_size];
    BN_bn2bin(private_key_bn, private_key);

    // Save private key shares into files
    save_private_key_shares("private_key", private_key, private_key_size, 5, 3); // example: 5 shares, threshold 3

    // Cleanup
    EC_KEY_free(key);
    ECDSA_SIG_free(signature);
    return 0;
}
