#include <iostream>
#include <vector>
#include <thread>
#include <csignal>
#include "DistributedWallet.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./server <port1> <port2> ..." << std::endl;
        return 1;
    }
    create_DB(argc-1);

    signal(SIGINT, signalHandler);  // <- Ctrl+C handler

    ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    ec_order = BN_new();
    bn_context = BN_CTX_new();
    EC_GROUP_get_order(ec_group, ec_order, nullptr);

    std::vector<std::thread> threads;

    for (int i = 1; i < argc; ++i) {
        int port = std::stoi(argv[i]);
        threads.emplace_back(runParticipantServer, port);
    }

    for (auto& t : threads) {
        t.join();
    }

    BN_free(ec_order);
    EC_GROUP_free(ec_group);
    BN_CTX_free(bn_context);
    std::cout << "All servers shutdown complete." << std::endl;
}
