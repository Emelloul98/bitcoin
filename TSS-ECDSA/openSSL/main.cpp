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

