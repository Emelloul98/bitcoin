#ifndef DISTRIBUTEDSIGNER_H
#define DISTRIBUTEDSIGNER_H

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

struct Signature {
    BIGNUM* r;
    BIGNUM* s;
};

namespace DistributedSigner {

void generateKeys(const std::string& publicKey, BIGNUM* privateKey);
Signature* signMessage(const std::string& publicKey, BIGNUM* messageHash);

void setThreshold(int newThreshold, int newParticipantCount);
void setSigningGroup(const std::vector<int>& ports);
void reconstructSecret(const std::string& publicKey, const std::vector<int>& ports);
} // namespace DistributedSigner

#endif // DISTRIBUTEDSIGNER_H