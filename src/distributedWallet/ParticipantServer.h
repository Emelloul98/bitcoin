#ifndef PARTICIPANTSERVER_H
#define PARTICIPANTSERVER_H
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
extern EC_GROUP* group;
extern BIGNUM* order;
extern BN_CTX* ctx;

void run_server(int port);
void create_DB(int n);
#endif //PARTICIPANTSERVER_H
