// g++ -o polynomial_generator polynomial_generator.cpp -lssl -lcrypto
#include <iostream>
#include <string>
#include <fstream>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

using namespace std;

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char *argv[])
{
    int t = atoi(argv[1]);
    int n = atoi(argv[2]);
    EC_GROUP *curve;
    BIGNUM ***coeff;
    BIGNUM **x;
    BIGNUM *s = BN_new();
    BIGNUM *order = BN_new();
    EC_POINT **X;
    EC_POINT *S;
    BN_CTX *bn_ctx = BN_CTX_new();

    if (NULL == (curve = EC_GROUP_new_by_curve_name(NID_secp256k1)))
        handleErrors();

    if (EC_GROUP_get_order(curve, order, bn_ctx) == 0) // return 1 on success and 0 if an error occurred
        handleErrors();

    coeff = new BIGNUM **[n];
    x = new BIGNUM *[n];
    X = new EC_POINT *[n];
    S = EC_POINT_new(curve);

    for (int i = 0; i < n; i++)
    {
        coeff[i] = new BIGNUM *[t + 1];
        x[i] = BN_new();
        X[i] = EC_POINT_new(curve);

        BN_zero(x[i]);
        for (int j = 0; j < t + 1; j++)
        {
            coeff[i][j] = BN_new();
            if (BN_rand_range(coeff[i][j], order) == 0)
                handleErrors();
        }
    }

    // compute the secret share s
    BN_zero(s);
    for (int i = 0; i < n; i++)
    {
        BN_mod_add(s, s, coeff[i][0], order, bn_ctx);
    }

    // copmute the public value S
    if (!EC_POINT_mul(curve, S, s, NULL, NULL, bn_ctx))
        handleErrors();

    // compute P(i)
    for (int cnt = 0; cnt < n; cnt++)
    {
        for (int i = 0; i < n; i++)
        {
            BIGNUM *index = BN_new();
            BIGNUM *tmp = BN_new(); // Pj(i)

            BN_zero(tmp);
            BN_dec2bn(&index, to_string(i + 1).c_str());

            for (int j = t; j >= 0; j--) // P_cnt(i)
            {
                BN_mod_mul(tmp, tmp, index, order, bn_ctx);
                BN_mod_add(tmp, tmp, coeff[cnt][j], order, bn_ctx);
            }

            BN_mod_add(x[i], x[i], tmp, order, bn_ctx);

            BN_free(index);
            BN_free(tmp);
        }
    }

    for (int i = 0; i < n; i++)
    {
        cout << "P" << i <<endl;
        if (!EC_POINT_mul(curve, X[i], x[i], NULL, NULL, bn_ctx))
            handleErrors();

        ofstream File;
        string name = "../data/P" + to_string(i + 1) + ".dat";
        File.open(name);

        if (t > n)
            handleErrors();

        File << t << ' ' << n << ' ' << i + 1 << "\n";

        char *buf = new char[1024];

        // output X
        memset(buf, 0x00, 1024);
        strcpy(buf, EC_POINT_point2hex(curve, S, EC_GROUP_get_point_conversion_form(curve), bn_ctx));
        File << buf << "\n";

        // output Xi
        memset(buf, 0x00, 1024);
        strcpy(buf, EC_POINT_point2hex(curve, X[i], EC_GROUP_get_point_conversion_form(curve), bn_ctx));
        File << buf << "\n";

        // output si
        memset(buf, 0x00, 1024);
        strcpy(buf, BN_bn2hex(x[i]));
        File << buf << "\n";


        // output Pi(x)
        for (int j = 0; j <= t; j++)
        {
            memset(buf, 0x00, 1024);

            strcpy(buf, BN_bn2hex(coeff[i][j]));
            File << buf << "\n";

            delete[] buf;
        }

        File.close();
    }

    return 0;
}