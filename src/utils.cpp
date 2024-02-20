#include "utils.hpp"

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}


void polinomial_generator(int t, int n, int lambda, unsigned char **_x, unsigned char **_X)
{ // need to check degree of polinomial.
    BN_CTX *bn_ctx = BN_CTX_new();
    EC_GROUP *curve;
    BIGNUM *order = BN_new(); // q
    const EC_POINT *G;
    BIGNUM **coeff = new BIGNUM *[t];

    BIGNUM **x = new BIGNUM *[n + 1];
    EC_POINT **X = new EC_POINT *[n + 1];

    switch (lambda)
    {
    case 160:
        if (NULL == (curve = EC_GROUP_new_by_curve_name(NID_secp160k1)))
            handleErrors();
        break;

    case 192:
        if (NULL == (curve = EC_GROUP_new_by_curve_name(NID_secp192k1)))
            handleErrors();
        break;

    case 224:
        if (NULL == (curve = EC_GROUP_new_by_curve_name(NID_secp224k1)))
            handleErrors();
        break;

    case 256:
    default:
        if (NULL == (curve = EC_GROUP_new_by_curve_name(NID_secp256k1)))
            handleErrors();
        break;
    }

    if (EC_GROUP_get_order(curve, order, bn_ctx) == 0) // return 1 on success and 0 if an error occurred
        handleErrors();

    if ((G = EC_GROUP_get0_generator(curve)) == NULL)
        handleErrors();

    for (int i = 0; i < t; i++)
    {
        coeff[i] = BN_new();
        if (!BN_rand_range(coeff[i], order))
            handleErrors();
    }
    for (int i = 0; i < n + 1; i++)
    {
        x[i] = BN_new();
        X[i] = EC_POINT_new(curve);

        BN_zero(x[i]);
    }

    for (int i = 0; i <= n; i++)
    {
        // BN_copy(x[0], coeff[0]);

        BIGNUM *index = BN_new();

        BN_zero(x[i]);
        BN_dec2bn(&index, to_string(i).c_str());

        for (int j = t - 1; j >= 0; j--) // P_cnt(i)
        {
            BN_mod_mul(x[i], x[i], index, order, bn_ctx);
            BN_mod_add(x[i], x[i], coeff[j], order, bn_ctx);
        }

        if (!EC_POINT_mul(curve, X[i], x[i], NULL, NULL, bn_ctx))
            handleErrors();
        strcpy((char *)_x[i], BN_bn2hex(x[i]));
        strcpy((char *)_X[i], EC_POINT_point2hex(curve, X[i], EC_GROUP_get_point_conversion_form(curve), bn_ctx));

        BN_free(index);
    }
}
