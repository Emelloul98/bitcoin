#ifndef DISTRIBUTEDWALLET_H
#define DISTRIBUTEDWALLET_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

extern EC_GROUP* ec_group;
extern BIGNUM* ec_order;
extern BN_CTX* bn_context;

void create_DB(int n);
void signalHandler(int signum);
void runParticipantServer(int port);

#endif // DISTRIBUTEDWALLET_H
