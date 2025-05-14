// === DistributedSigner.cpp ===
#include "DistributedSigner.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ec.h>

// === Static members initialization ===
EC_GROUP* DistributedSigner::group = []() {
    return EC_GROUP_new_by_curve_name(NID_secp256k1);
}();

BIGNUM* DistributedSigner::order = []() {
    BIGNUM* ord = BN_new();
    EC_GROUP_get_order(DistributedSigner::group, ord, nullptr);
    return ord;
}();

BN_CTX* DistributedSigner::ctx = BN_CTX_new();

DistributedSigner::CleanupHelper DistributedSigner::cleanup_guard;

BIGNUM* DistributedSigner:: generate_random_zq() {
    BIGNUM* ord = BN_dup(order);
    BN_sub_word(ord, 1);
    BIGNUM* res = BN_new();
    BN_rand_range(res, ord);
    BN_add_word(res, 1);
    BN_free(ord);
    return res;
}
std::string DistributedSigner::send_to_participant(std::string pub_str, int port, const std::string& in_message) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket failed");
        return "ERROR_SOCKET";
    }
    std::string message = pub_str + " " + in_message;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect failed");
        close(sock);
        return "ERROR_CONNECT";
    }

    if (send(sock, message.c_str(), message.size(), 0) < 0) {
        perror("send failed");
        close(sock);
        return "ERROR_SEND";
    }


    char buffer[1024] = {};
    int read_bytes = read(sock, buffer, sizeof(buffer) - 1);
    if (read_bytes <= 0) {
        close(sock);
        return "";
    }
    close(sock);
    return std::string(buffer);
}

std::vector<BIGNUM *> DistributedSigner::generate_polynomial_t(BIGNUM *x)
{
    std::vector<BIGNUM *> coefficients;
    coefficients.push_back(BN_dup(x));
    for (int i = 1; i < t; i++)
    {
        coefficients.push_back(generate_random_zq());
    }
    return coefficients;
}


/*
 *  evaluate_polynomial function:
 *  1.Calculates the value of the given polynomial at the point x.
 *  2.return the result f(x).
 */
BIGNUM *DistributedSigner::evaluate_polynomial(const std::vector<BIGNUM *> &coefficients, int x)
{
    BIGNUM *result = BN_new();  // Final result
    BIGNUM *temp = BN_new();    // Temporary variable for intermediate computations
    BIGNUM *x_power = BN_new(); // Holds x^i

    BN_zero(result); // Initialize result to 0
    BN_one(x_power); // x^0 = 1

    for (size_t i = 0; i < coefficients.size(); i++)
    {
        // temp = coefficients[i] * x_power mod order
        BN_mod_mul(temp, coefficients[i], x_power, order, ctx);

        // result = result + temp mod order
        BN_mod_add(result, result, temp, order, ctx);

        // x_power = x_power * x mod order
        BN_mul_word(x_power, x); // x_power *= x
    }

    BN_free(temp);
    BN_free(x_power);

    return result;
}


void DistributedSigner::generateKeys(std::string pub_str, BIGNUM *privateKey)
{
    std::vector<int> ports = {5000, 5001, 5002};

    // shamir polynomial creation:
    std::vector<BIGNUM *> polynomial = generate_polynomial_t(privateKey);

    // Send each f(i) to its respective server
    for (size_t i = 0; i < ports.size(); ++i) {
        BIGNUM* secret = evaluate_polynomial(polynomial, i + 1);
        char* secret_hex = BN_bn2hex(secret);
        send_to_participant(pub_str, ports[i], std::string("store polynomial_secret ") + secret_hex + "\n");
        OPENSSL_free(secret_hex);
        BN_free(secret);
    }

    for (auto coeff : polynomial) BN_free(coeff);
}

BIGNUM* DistributedSigner::str_to_bn(const std::string& hex) {
    BIGNUM* res = nullptr;
    BN_hex2bn(&res, hex.c_str());
    return res;
}

BIGNUM* DistributedSigner::H0(const EC_POINT* point) {
    BIGNUM* x = BN_new();
    BIGNUM* result = BN_new();
    if (!EC_POINT_get_affine_coordinates(group, point, x, nullptr, ctx)) {
        BN_free(x); BN_free(result); return nullptr;
    }
    BN_mod(result, x, order, ctx);
    BN_free(x);
    return result;
}



void DistributedSigner::compute_sigma(std::string pub_str, const std::vector<int>& ports)
{
    // Create temporary BIGNUM variables for computation.
    BIGNUM *num = BN_new();  // numerator
    BIGNUM *den = BN_new();  // denominator
    BIGNUM *inv = BN_new();  // inverse of denominator
    BIGNUM *temp = BN_new(); // temporary product
    BIGNUM * k_sum = BN_new();
    // We'll store gamma for each participant in signingGroup in a map.
    // key: participant index (as used in signingGroup)
    std::map<int, BIGNUM*> gammaMap;
    std::vector<int> signingGroup = {0, 1};

    // For each participant i in the signing group,
    // initialize gamma_i to 1 and update it based on other participants.
    for (int i : signingGroup) {
        BIGNUM* gamma_i = BN_new();
        // set gamma_i = 1:
        BN_one(gamma_i);
        for (int j : signingGroup) {
            if (j == i)
                continue;
            // num = (j + 1)
            BN_set_word(num, j + 1);
            // den = |j - i|
            BN_set_word(den, std::abs(j - i));
            if ((j - i) < 0) {
                BN_set_negative(den, 1);
            }
            // Compute modular inverse of den (inv = den^(-1) mod order)
            if (!BN_mod_inverse(inv, den, order, ctx)) {
                std::cerr << "Error computing modular inverse." << std::endl;
            }
            // Compute temp = (num * inv) mod order
            BN_mod_mul(temp, num, inv, order, ctx);
            // Update gamma_i = (gamma_i * temp) mod order
            BN_mod_mul(gamma_i, gamma_i, temp, order, ctx);
        }
        gammaMap[i] = gamma_i;
    }


    // For each participant i, compute w_i = gamma_i * x_i mod order. (x_i is the Shamir share)
    BN_zero(k_sum);


    for (size_t idx = 0; idx < ports.size(); ++idx) {
        int port = ports[idx];
        int participant_index = idx + 1; // for naming consistency

        // Get x_i = f(i)
        std::string x_str = send_to_participant(pub_str, port, "get polynomial_secret\n");

        BIGNUM* x_i = str_to_bn(x_str);

        // Get k_i
        std::string k_str = send_to_participant(pub_str, port, "get k\n");
        BIGNUM* k_i = str_to_bn(k_str);

        // k_sum += k_i
        BN_mod_add(k_sum, k_sum, k_i, order, ctx);

        // gamma_i was computed locally beforehand
        BIGNUM* w_i = BN_new();
        BN_mod_mul(w_i, gammaMap[participant_index - 1], x_i, order, ctx);

        // Send w_i back to participant file
        char* w_hex = BN_bn2hex(w_i);
        send_to_participant(pub_str, port, std::string("store w ") + w_hex + "\n");
        OPENSSL_free(w_hex);

        // Clean up
        BN_free(x_i);
        BN_free(k_i);
        BN_free(w_i);
    }

    // Now, compute sigma for each participant i:
    // sigma_i = sum_{j in signingGroup} ( k_j * w_i ) mod order.
    for (size_t idx = 0; idx < ports.size(); ++idx) {
        int port = ports[idx];

        // Get w_i from server
        std::string w_str = send_to_participant(pub_str, port, "get w\n");
        BIGNUM* w_i = str_to_bn(w_str);

        // Compute sigma_i = k_sum * w_i mod order
        BIGNUM* sigma_i = BN_new();
        BN_mod_mul(sigma_i, k_sum, w_i, order, ctx);

        // Send sigma_i to participant file
        char* sigma_hex = BN_bn2hex(sigma_i);
        send_to_participant(pub_str, port, std::string("store sigma ") + sigma_hex + "\n");
        OPENSSL_free(sigma_hex);

        BN_free(w_i);
        BN_free(sigma_i);
    }


    // clean-up:
    BN_free(temp);
    BN_free(num);
    BN_free(den);
    BN_free(inv);
    BN_free(k_sum);
    for (auto &entry : gammaMap) {
        BN_free(entry.second);
    }
}

Signature* DistributedSigner::signMessage(std::string pub_str, BIGNUM* msgHash, const std::vector<int>& ports) {
    Signature* sig = new Signature();

    for (int port : ports) {
        send_to_participant(pub_str, port, "generate_k_and_y\n");
    }

    BIGNUM* k_sum = BN_new();
    BIGNUM* y_sum = BN_new();
    BN_zero(k_sum); BN_zero(y_sum);
    for (int port : ports) {
        BIGNUM* k = str_to_bn(send_to_participant(pub_str, port, "get k\n"));
        BIGNUM* y = str_to_bn(send_to_participant(pub_str, port, "get y\n"));
        BN_mod_add(k_sum, k_sum, k, order, ctx);
        BN_mod_add(y_sum, y_sum, y, order, ctx);
        BN_free(k); BN_free(y);
    }
    BIGNUM* ky = BN_new();
    BN_mod_mul(ky, k_sum, y_sum, order, ctx);
    BN_free(k_sum); BN_free(y_sum);

    BIGNUM* delta_inv = BN_mod_inverse(nullptr, ky, order, ctx);
    BN_free(ky);
    char* delta_hex = BN_bn2hex(delta_inv);
    BN_free(delta_inv);

    EC_POINT* R = EC_POINT_new(group);
    EC_POINT_set_to_infinity(group, R);

    for (int port : ports) {
        std::string response = send_to_participant(pub_str, port, std::string("compute_R ") + delta_hex + "\n");
        // Convert Ri from hex response
        EC_POINT* Ri = EC_POINT_new(group);
        EC_POINT_hex2point(group, response.c_str(), Ri, ctx);
        EC_POINT_add(group, R, R, Ri, ctx);
        EC_POINT_free(Ri);
    }
    OPENSSL_free(delta_hex);

    sig->r = H0(R);
    EC_POINT_free(R);

    compute_sigma(pub_str, ports);

    sig->s = BN_new(); BN_zero(sig->s);
    for (int port : ports) {
        BIGNUM* k = str_to_bn(send_to_participant(pub_str, port, "get k\n"));
        BIGNUM* sigma = str_to_bn(send_to_participant(pub_str, port, "get sigma\n"));
        BIGNUM* temp = BN_new();
        BIGNUM* s_partial = BN_new();
        BN_mod_mul(temp, sig->r, sigma, order, ctx);
        BN_mod_mul(s_partial, k, msgHash, order, ctx);
        BN_mod_add(s_partial, s_partial, temp, order, ctx);
        BN_mod_add(sig->s, sig->s, s_partial, order, ctx);
        BN_free(k); BN_free(sigma); BN_free(temp); BN_free(s_partial);
    }

    BIGNUM* half_order = BN_new();
    BN_rshift1(half_order, order);
    if (BN_cmp(sig->s, half_order) > 0) {
        BN_sub(sig->s, order, sig->s);
    }
    BN_free(half_order);
    return sig;
}

void DistributedSigner::cleanup() {
    EC_GROUP_free(group);
    BN_free(order);
    BN_CTX_free(ctx);
}
