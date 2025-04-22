#include "simpleECDSA.hpp"
/*
 *  simpleECDSA class constructor
*/
simpleECDSA:: simpleECDSA(int threshold, int total_participants)
        : t(threshold), n(total_participants)
{
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    order = BN_new();
    EC_GROUP_get_order(group, order, nullptr);
    std::cout << "order: " << BN_bn2hex(order) << std::endl;
    publicKey = EC_POINT_new(group);

    EC_POINT_set_to_infinity(group, publicKey);
    generator = EC_POINT_new(group);
    EC_POINT_copy(generator, EC_GROUP_get0_generator(group));
    ctx = BN_CTX_new();
    char* gen_str = EC_POINT_point2hex(group, generator, POINT_CONVERSION_UNCOMPRESSED, ctx);//prints
    std::cout << "Generator point G: " << gen_str << std::endl; // prints
    OPENSSL_free(gen_str);//prints
    for (int i = 0; i < total_participants; i++) {
        std::string filename = "participant_" + std::to_string(i+1) + ".dat";
        std::ofstream outfile(filename);
        if (outfile.is_open()) {
            outfile << "# Secret data for participant" << (i) << "\n";
            outfile.close();
            std::cout << "Created file: " << filename << std::endl;
        } else {
            std::cerr << "Error: could not create file " << filename << std::endl;
        }
    }
}
