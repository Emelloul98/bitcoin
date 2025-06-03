// === DistributedSigner.cpp ===
#include "DistributedSigner.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ec.h>
#include <numeric>
#include <fstream>
#include <string>

namespace DistributedSigner {


    // === Hidden variables ===
    static int threshold = 2;
    static int participantCount = 3;
    const int firstParticipantPort = 5000;
    static std::vector<int> signingGroup = {5000, 5001};

    BIGNUM* curveOrder = nullptr;
    EC_GROUP* curveGroup = nullptr;
    BN_CTX* bnContext = nullptr;

    /**
     * @brief Initialize elliptic curve parameters for secp256k1.
     */
    void initializeCryptoParameters() {
        curveGroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
        curveOrder = BN_new();
        EC_GROUP_get_order(curveGroup, curveOrder, nullptr);
        bnContext = BN_CTX_new();
    }

    /**
     * @brief Cleanup allocated elliptic curve resources.
     */
    void cleanupCryptoParameters() {
        if (curveGroup) EC_GROUP_free(curveGroup);
        curveGroup = nullptr;
        if (curveOrder) BN_free(curveOrder);
        curveOrder = nullptr;
        if (bnContext) BN_CTX_free(bnContext);
        bnContext = nullptr;
    }

// === Public functions ===
    void setThreshold(int newThreshold, int newParticipantCount) {
         if (newThreshold <= 0 || newParticipantCount <= 0 || newThreshold > newParticipantCount) {
             throw std::invalid_argument("Invalid threshold values: t > 0, n > 0, and t <= n.");
         }
        threshold = newThreshold;
        participantCount = newParticipantCount;

        signingGroup.resize(threshold);
        std::iota(signingGroup.begin(), signingGroup.end(), firstParticipantPort);
    }
    void setSigningGroup(const std::vector<int>& ports) {
		if (ports.size() < static_cast<size_t>(threshold)) {
        	throw std::invalid_argument("Number of setSigningGroup is less than threshold");
    	}
        signingGroup = ports;
    }

    BIGNUM* generateRandomInZq() {
        BIGNUM* tempOrder = BN_dup(curveOrder);
        BN_sub_word(tempOrder, 1);
        BIGNUM* result = BN_new();
        BN_rand_range(result, tempOrder);
        BN_add_word(result, 1);
        BN_free(tempOrder);
        return result;
    }
    std::string sendCommandToParticipant(const std::string& publicKey, int port, const std::string& message) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket failed");
            return "ERROR_SOCKET";
        }

        std::string fullMessage = publicKey + " " + message;

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = inet_addr("127.0.0.1");

        if (connect(sock, (sockaddr*)&address, sizeof(address)) < 0) {
            perror("connect failed");
            close(sock);
            return "ERROR_CONNECT";
        }

        if (send(sock, fullMessage.c_str(), fullMessage.size(), 0) < 0) {
            perror("send failed");
            close(sock);
            return "ERROR_SEND";
        }

        char buffer[1024] = {};
        int bytesRead = read(sock, buffer, sizeof(buffer) - 1);
        close(sock);

        return (bytesRead > 0) ? std::string(buffer) : "";
    }

    std::vector<BIGNUM*> generatePolynomialCoefficients(BIGNUM* constantTerm) {
        std::vector<BIGNUM*> coefficients{ BN_dup(constantTerm) };
        for (int i = 1; i < threshold; ++i) {
            coefficients.push_back(generateRandomInZq());
        }
        return coefficients;
    }

    /*
    *  evaluate_polynomial function:
    *  1.Calculates the value of the given polynomial at the point x.
    *  2.return the result f(x).
    */
    BIGNUM* evaluatePolynomialAtX(const std::vector<BIGNUM*>& coefficients, int xValue) {
        BIGNUM* result = BN_new();
        BIGNUM* term = BN_new();
        BIGNUM* xPower = BN_new();

        BN_zero(result);
        BN_one(xPower);

        for (const auto& coeff : coefficients) {
            BN_mod_mul(term, coeff, xPower, curveOrder, bnContext);
            BN_mod_add(result, result, term, curveOrder, bnContext);
            BN_mul_word(xPower, xValue);
        }

        BN_free(term);
        BN_free(xPower);

        return result;
    }

    void generateKeys(const std::string& publicKey, BIGNUM* privateKey) {
        initializeCryptoParameters();

        std::vector<int> ports(participantCount);
        std::iota(ports.begin(), ports.end(), 5000);

        auto polynomialCoefficients = generatePolynomialCoefficients(privateKey);

        for (size_t i = 0; i < ports.size(); ++i) {
            BIGNUM* secretShare = evaluatePolynomialAtX(polynomialCoefficients, i + 1);
            char* secretHex = BN_bn2hex(secretShare);
            sendCommandToParticipant(publicKey, ports[i], "store polynomial_secret " + std::string(secretHex) + "\n");
            OPENSSL_free(secretHex);
            BN_free(secretShare);
        }

        for (auto& coeff : polynomialCoefficients) BN_free(coeff);

        cleanupCryptoParameters();
    }


     BIGNUM* hexStringToBignum(const std::string& hexString) {
        BIGNUM* result = nullptr;
        BN_hex2bn(&result, hexString.c_str());
        return result;
     }

    BIGNUM* hashPointToBignum(const EC_POINT* point) {
        BIGNUM* xCoord = BN_new();
        BIGNUM* hashedValue = BN_new();
        if (!EC_POINT_get_affine_coordinates(curveGroup, point, xCoord, nullptr, bnContext)) {
            BN_free(xCoord); BN_free(hashedValue);
            return nullptr;
        }
        BN_mod(hashedValue, xCoord, curveOrder, bnContext);
        BN_free(xCoord);
        return hashedValue;
    }


    void computeSigmaValues(const std::string& publicKey) {
        BIGNUM *numerator = BN_new(), *denominator = BN_new(), *inverseDen = BN_new();
        BIGNUM *tempProduct = BN_new(), *kSum = BN_new();
        BN_zero(kSum);

        // We'll store gamma for each participant in signingGroup in a map.
        // key: participant index (as used in signingGroup)
        std::map<int, BIGNUM*> lagrangeCoefficients;

        // For each participant i in the signing group,
        // initialize gamma_i to 1 and update it based on other participants.
        for (int tempIdxI : signingGroup) {
            int i = tempIdxI - firstParticipantPort;
            BIGNUM* gamma = BN_new(); BN_one(gamma);
            for (int tempIdxJ : signingGroup) {
                int j = tempIdxJ - firstParticipantPort;
                if (j == i) continue;
                BN_set_word(numerator, j + 1);
                BN_set_word(denominator, std::abs(j - i));
                if ((j - i) < 0) BN_set_negative(denominator, 1);
                if (!BN_mod_inverse(inverseDen, denominator, curveOrder, bnContext)) {
                    std::cerr << "Error computing inverse." << std::endl;
                }
                BN_mod_mul(tempProduct, numerator, inverseDen, curveOrder, bnContext);
                BN_mod_mul(gamma, gamma, tempProduct, curveOrder, bnContext);
            }
            lagrangeCoefficients[i] = gamma;
        }

        for (size_t idx = 0; idx < signingGroup.size(); ++idx) {
            std::string xStr = sendCommandToParticipant(publicKey, signingGroup[idx], "get polynomial_secret\n");
            std::string kStr = sendCommandToParticipant(publicKey, signingGroup[idx], "get k\n");

            BIGNUM* x_i = hexStringToBignum(xStr);
            BIGNUM* k_i = hexStringToBignum(kStr);

            BN_mod_add(kSum, kSum, k_i, curveOrder, bnContext);

            BIGNUM* w_i = BN_new();
            BN_mod_mul(w_i, lagrangeCoefficients[signingGroup[idx] - firstParticipantPort], x_i, curveOrder, bnContext);

            char* wHex = BN_bn2hex(w_i);
            sendCommandToParticipant(publicKey, signingGroup[idx], "store w " + std::string(wHex) + "\n");

            OPENSSL_free(wHex);
            BN_free(x_i); BN_free(k_i); BN_free(w_i);
        }

        // Now, compute sigma for each participant i:
        // sigma_i = sum_{j in signingGroup} ( k_j * w_i ) mod order.
        for (size_t idx = 0; idx < signingGroup.size(); ++idx) {
            std::string wStr = sendCommandToParticipant(publicKey, signingGroup[idx], "get w\n");
            BIGNUM* w_i = hexStringToBignum(wStr);

            BIGNUM* sigma_i = BN_new();
            BN_mod_mul(sigma_i, kSum, w_i, curveOrder, bnContext);

            char* sigmaHex = BN_bn2hex(sigma_i);
            sendCommandToParticipant(publicKey, signingGroup[idx], "store sigma " + std::string(sigmaHex) + "\n");

            OPENSSL_free(sigmaHex);
            BN_free(w_i); BN_free(sigma_i);
        }
        // clean-up:
        BN_free(numerator); BN_free(denominator); BN_free(inverseDen);
        BN_free(tempProduct); BN_free(kSum);
        for (auto& entry : lagrangeCoefficients) BN_free(entry.second);
    }

    Signature* signMessage(const std::string& publicKey, BIGNUM* messageHash) {
        initializeCryptoParameters();

	std::ofstream sigOut("partial_signatures.txt", std::ios::out);
        if (!sigOut.is_open()) {
            std::cerr << "Failed to open partial_signatures.txt" << std::endl;
        }else{
            char* hexStr = BN_bn2hex(messageHash);
            sigOut << "Message hash: " << hexStr << std::endl;
            OPENSSL_free(hexStr);
        }
        Signature* signature = new Signature();

        for (int port : signingGroup) {
            sendCommandToParticipant(publicKey, port, "generate_k_and_y\n");
        }

        BIGNUM *kSum = BN_new(), *ySum = BN_new();
        BN_zero(kSum); BN_zero(ySum);

        for (int port : signingGroup) {
            BIGNUM* k = hexStringToBignum(sendCommandToParticipant(publicKey, port, "get k\n"));
            BIGNUM* y = hexStringToBignum(sendCommandToParticipant(publicKey, port, "get y\n"));
            BN_mod_add(kSum, kSum, k, curveOrder, bnContext);
            BN_mod_add(ySum, ySum, y, curveOrder, bnContext);
            BN_free(k); BN_free(y);
        }

        BIGNUM* kyProduct = BN_new();
        BN_mod_mul(kyProduct, kSum, ySum, curveOrder, bnContext);
        BN_free(kSum); BN_free(ySum);

        BIGNUM* deltaInv = BN_mod_inverse(nullptr, kyProduct, curveOrder, bnContext);
        BN_free(kyProduct);

        char* deltaHex = BN_bn2hex(deltaInv);
        BN_free(deltaInv);

        EC_POINT* aggregatedR = EC_POINT_new(curveGroup);
        EC_POINT_set_to_infinity(curveGroup, aggregatedR);

        for (int port : signingGroup) {
            std::string RStr = sendCommandToParticipant(publicKey, port, "compute_R " + std::string(deltaHex) + "\n");
            EC_POINT* Ri = EC_POINT_new(curveGroup);
            EC_POINT_hex2point(curveGroup, RStr.c_str(), Ri, bnContext);
            EC_POINT_add(curveGroup, aggregatedR, aggregatedR, Ri, bnContext);
            EC_POINT_free(Ri);
        }

        OPENSSL_free(deltaHex);
        signature->r = hashPointToBignum(aggregatedR);
        EC_POINT_free(aggregatedR);

        computeSigmaValues(publicKey);

        signature->s = BN_new(); BN_zero(signature->s);

        for (int port : signingGroup) {
            BIGNUM* k = hexStringToBignum(sendCommandToParticipant(publicKey, port, "get k\n"));
            BIGNUM* sigma = hexStringToBignum(sendCommandToParticipant(publicKey, port, "get sigma\n"));

            BIGNUM* tempMul = BN_new();
            BIGNUM* partialS = BN_new();

            BN_mod_mul(tempMul, signature->r, sigma, curveOrder, bnContext);
            BN_mod_mul(partialS, k, messageHash, curveOrder, bnContext);
            BN_mod_add(partialS, partialS, tempMul, curveOrder, bnContext);
            BN_mod_add(signature->s, signature->s, partialS, curveOrder, bnContext);

            if (sigOut.is_open()) {
                char* sigStr = BN_bn2hex(partialS);
                sigOut << "Storage" << (port-4999) << " signature:\n" << sigStr << std::endl;
                OPENSSL_free(sigStr);
            }

            BN_free(k); BN_free(sigma);
            BN_free(tempMul); BN_free(partialS);
        }
        if (sigOut.is_open()) {
            char* combinedSignature = BN_bn2hex(signature->s);
            sigOut << "Combined signature: " << combinedSignature << std::endl;
            OPENSSL_free(combinedSignature);
	    sigOut.close();
        }
        BIGNUM* halfOrder = BN_new();
        BN_rshift1(halfOrder, curveOrder);
        if (BN_cmp(signature->s, halfOrder) > 0) {
            BN_sub(signature->s, curveOrder, signature->s);
        }
        BN_free(halfOrder);

        cleanupCryptoParameters();

        return signature;
    }


    // Reconstruct f(0) using Lagrange interpolation
    BIGNUM* lagrangeInterpolationAtZero(const std::vector<std::pair<int, BIGNUM*>>& points) {
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* result = BN_new();
        BN_zero(result);

        for (size_t i = 0; i < points.size(); ++i) {
            int xi = points[i].first;
            BIGNUM* yi = points[i].second;

            BIGNUM* li = BN_new();
            BN_one(li);

            for (size_t j = 0; j < points.size(); ++j) {
                if (i == j) continue;

                int xj = points[j].first;

                // Create BIGNUMs
                BIGNUM *num = BN_new();       // numerator = -xj mod p
                BIGNUM *den = BN_new();       // denominator = (xi - xj) mod p
                BIGNUM *den_inv = BN_new();   // inverse of denominator
                BIGNUM *term = BN_new();      // term = num * den_inv mod p
                BIGNUM *xi_bn = BN_new();
                BIGNUM *xj_bn = BN_new();

                // num = (-xj) mod p
                BN_set_word(xj_bn, xj);
                BN_mod_sub(num, BN_value_one(), xj_bn, curveOrder, ctx); // temporary but incorrect
                BN_zero(num);
                BN_mod_sub(num, num, xj_bn, curveOrder, ctx); // num = (0 - xj) mod p

                // den = (xi - xj) mod p
                BN_set_word(xi_bn, xi);
                BN_mod_sub(den, xi_bn, xj_bn, curveOrder, ctx);

                // den_inv = (xi - xj)^(-1) mod p
                BN_mod_inverse(den_inv, den, curveOrder, ctx);

                // term = num * den_inv mod p
                BN_mod_mul(term, num, den_inv, curveOrder, ctx);

                // li *= term mod p
                BN_mod_mul(li, li, term, curveOrder, ctx);

                // Free temporary variables
                BN_free(num);
                BN_free(den);
                BN_free(den_inv);
                BN_free(term);
                BN_free(xi_bn);
                BN_free(xj_bn);
            }

            // result += yi * li mod p
            BIGNUM* product = BN_new();
            BN_mod_mul(product, yi, li, curveOrder, ctx);

            BN_mod_add(result, result, product, curveOrder, ctx);

            BN_free(li);
            BN_free(product);
        }

        BN_CTX_free(ctx);
        return result;
    }

    bool CheckPrivateMatchesPublic(const std::string& publicKeyHex, const BIGNUM* secret) {
    EC_POINT* pubPoint = EC_POINT_new(curveGroup);
    EC_POINT* derivedPoint = EC_POINT_new(curveGroup);

    if (!EC_POINT_hex2point(curveGroup, publicKeyHex.c_str(), pubPoint, bnContext)) {
        EC_POINT_free(pubPoint);
        EC_POINT_free(derivedPoint);
        cleanupCryptoParameters();
        throw std::invalid_argument("Invalid public key format");
    }

    if (!EC_POINT_mul(curveGroup, derivedPoint, secret, nullptr, nullptr, bnContext)) {
        EC_POINT_free(pubPoint);
        EC_POINT_free(derivedPoint);
        cleanupCryptoParameters();
        throw std::runtime_error("Failed to compute public key from private key");
    }

    bool matches = (EC_POINT_cmp(curveGroup, pubPoint, derivedPoint, bnContext) == 0);

    EC_POINT_free(pubPoint);
    EC_POINT_free(derivedPoint);
    return matches;
}
    void reconstructSecret(const std::string& publicKey, const std::vector<int>& ports) {
        if (ports.size() < static_cast<size_t>(threshold)) {
        	throw std::invalid_argument("Number of secrets is less than threshold");
    	}
        initializeCryptoParameters();

        std::vector<std::pair<int, BIGNUM*>> points;

        for (size_t i = 0; i < ports.size(); ++i) {
            BIGNUM* y = hexStringToBignum(sendCommandToParticipant(publicKey, ports[i], "get polynomial_secret\n"));
            points.emplace_back(ports[i] - firstParticipantPort + 1, y);
        }

        BIGNUM* secret = lagrangeInterpolationAtZero(points);

        for (auto& [x, y] : points) {
            BN_free(y);
        }
        bool isMatchesPublic = CheckPrivateMatchesPublic(publicKey, secret);
        cleanupCryptoParameters();
        if (!isMatchesPublic) {
            throw std::invalid_argument("Reconstructed secret key does not match the given public key.");
        }
        generateKeys(publicKey,secret);
    }
}