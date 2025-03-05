#include "ThresholdECDSA.hpp"


BIGNUM *ThresholdECDSA::generate_random_zq()
{
    BIGNUM *res = BN_new();
    BN_rand_range(res, order);
    return res;
}


std::vector<BIGNUM *> ThresholdECDSA::generate_polynomial_t(BIGNUM *ui)
{
    std::vector<BIGNUM *> coefficients;
    coefficients.push_back(BN_dup(ui));
    for (int i = 1; i < t; i++)
    {
        coefficients.push_back(generate_random_zq());
    }
    return coefficients;
}

BIGNUM *ThresholdECDSA::evaluate_polynomial(const std::vector<BIGNUM *> &coefficients, int x)
{
    BIGNUM *result = BN_new();  
    BIGNUM *temp = BN_new();    
    BIGNUM *x_power = BN_new(); 
    BN_CTX *ctx = BN_CTX_new(); 

    BN_zero(result); 
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
    BN_CTX_free(ctx);

    return result;
}

ThresholdECDSA:: ThresholdECDSA(int threshold, int total_participants)
    : t(threshold), n(total_participants)
{
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    order = BN_new();
    EC_GROUP_get_order(group, order, nullptr);
    publicKey = EC_POINT_new(group);
    
   
    //if (!EC_POINT_copy(publicKey, EC_GROUP_get0_generator(group))) {
    //    std:: cout << "ctxv";
    //}

    EC_POINT_set_to_infinity(group, publicKey);
    generator = EC_POINT_new(group);
    EC_POINT_copy(generator, EC_GROUP_get0_generator(group));

    for (int i = 1; i <= n; i++)
    {
        Participant* data = new Participant();
        generate_participant_data(i, *data);
        participants.push_back(data);
    }
}
void ThresholdECDSA:: generate_participant_data(int participant_id, Participant &participant)
{
    BN_CTX *ctx = BN_CTX_new();
    participant.participant_id = participant_id;
    BN_rand_range(participant.k, order);
    BN_rand_range(participant.gamma, order);
    BN_rand_range(participant.u, order);

    std::vector<BIGNUM *> polynomial = generate_polynomial_t(participant.u);

    participant.y = EC_POINT_new(group);
    EC_POINT_mul(group, participant.y, participant.u, nullptr, nullptr, ctx);

    for (int i = 1; i <= n; i++)
    {
        BIGNUM *share = evaluate_polynomial(polynomial, i);
        participant.shares.push_back(share);
    }

    for (auto coeff : polynomial)
        BN_free(coeff);
    BN_CTX_free(ctx);
}

