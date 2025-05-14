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

void generateKeys(const std::string& pub_str, BIGNUM* privateKey);
Signature* signMessage(const std::string& pub_str, BIGNUM* msgHash, const std::vector<int>& ports);

void set_threshold(int new_t, int new_n);

} // namespace DistributedSigner

#endif // DISTRIBUTEDSIGNER_H
