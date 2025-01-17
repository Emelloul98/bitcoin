#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <string>
#include <sstream>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

EC_KEY* global_pub_key = nullptr;

using namespace std;

// Function to generate distributed keys using Shamir's Secret Sharing
void createDistributedKeys(int numParticipants, int threshold) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(1, 1e6); // Random number range

    // Generate group private key (randomly)
    BIGNUM* groupPrivateKey = BN_new();
    BN_rand(groupPrivateKey, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

    vector<BIGNUM*> shares(threshold);
    for (int i = 0; i < threshold - 1; ++i) {
        shares[i] = BN_new();
        BN_rand(shares[i], 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    }

    // Calculate the final share so that the sum matches the private key
    shares[threshold - 1] = BN_new();
    BIGNUM* sum = BN_new();
    BN_zero(sum);

    for (int i = 0; i < threshold - 1; ++i) {
        BN_add(sum, sum, shares[i]);
    }
    BN_sub(shares[threshold - 1], groupPrivateKey, sum);

    // Save shares to files
    for (int i = 0; i < numParticipants; ++i) {
        string filename = "participant_" + to_string(i + 1) + ".key";
        ofstream file(filename);
        if (file.is_open()) {
            char* hex = BN_bn2hex(shares[i % threshold]);
            file << hex;
            OPENSSL_free(hex);
            file.close();
            cout << "Saved share to " << filename << endl;
        } else {
            cerr << "Unable to open file " << filename << endl;
        }
    }

    
    // Create public key
    global_pub_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT* pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, groupPrivateKey, NULL, NULL, NULL); 
    EC_KEY_set_public_key(global_pub_key, pub);

    EC_POINT_free(pub);
    EC_GROUP_free(group);

    // Cleanup
    for (auto share : shares) {
        BN_free(share);
    }
    BN_free(sum);
    BN_free(groupPrivateKey);
}

// Function to sign a message using partial ECDSA signatures
string signMessage(const string& message, const vector<string>& keyFiles) {
    vector<BIGNUM*> partialSignatures;

    // Hash the message using SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message.c_str(), message.size(), hash);

    for (const string& file : keyFiles) {
        ifstream keyFile(file);
        if (keyFile.is_open()) {
            string hexKey;
            keyFile >> hexKey;
            BIGNUM* partialKey = BN_new();
            BN_hex2bn(&partialKey, hexKey.c_str());

            // Create a partial signature (simplified for demonstration purposes)
            BIGNUM* partialSig = BN_new();
            BN_bin2bn(hash, SHA256_DIGEST_LENGTH, partialSig);
            BN_add(partialSig, partialSig, partialKey);
            partialSignatures.push_back(partialSig);

            keyFile.close();
        } else {
            cerr << "Unable to open key file: " << file << endl;
        }
    }

    // Combine partial signatures to form the final signature
    BIGNUM* finalSignature = BN_new();
    BN_zero(finalSignature);

    for (auto sig : partialSignatures) {
        BN_add(finalSignature, finalSignature, sig);
        BN_free(sig);
    }

    // Convert the final signature to a string
    char* hexSig = BN_bn2hex(finalSignature);
    string result(hexSig);
    OPENSSL_free(hexSig);
    BN_free(finalSignature);

    return result;
}

int main() {
    int numParticipants = 5;
    int threshold = 3;

    // Create distributed keys
    createDistributedKeys(numParticipants, threshold);
    // Sign message
    string message = "Hello, Threshold ECDSA!";
    vector<string> keyFiles = {"participant_1.key", "participant_2.key", "participant_3.key"};
    string signature = signMessage(message, keyFiles);
    cout << "Signature: " << signature << endl;

    cout << global_pub_key << endl;
    EC_KEY_free(global_pub_key);

    return 0;
}

