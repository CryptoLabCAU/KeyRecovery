// g++ -o our_recovery our_recovery.cpp parties.cpp -lssl -lcrypto

#include "../include/parties.h"
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <fstream>

#define STR_LENGTH 512
#define Zp_SPACE 256
#define G_SPACE 512
#define CIPHERTEXT_SPACE 1024

#define TESTCNT 100

// int t, n, lambda;

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

// void parse_option(int argc, char *argv[])
// {
//     const char *opt = "n:t:l:N:T:L:";
//     char option;
//     char *c;
//     string str;

//     while ((option = getopt(argc, argv, opt)) != -1)
//     {
//         switch (option)
//         {
//         case 't':
//         case 'T':
//             t = atoi(optarg);

//         case 'n':
//         case 'N':
//             n = atoi(optarg);
//             break;
//         case 'l':
//         case 'L':
//             lambda = atoi(optarg);
//             break;

//         default:
//             break;
//         }
//     }
// }

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

int main(int argc, char *argv[])
{

    // parse_option(argc, argv);
    for (int lambda = 160; lambda <= 256; lambda += 32)
    {
        for (int t = 2, n = 3; t <= 15; t++, n++)
        {
            double t0 = 0, t1 = 0;
            double p1 = 0, p2 = 0, p3 = 0;
            for (int TEST = 0; TEST < TESTCNT; TEST++)
            {

                PARTIES **P = new PARTIES *[n];

                BIGNUM **s = new BIGNUM *[n + 1];
                BIGNUM ***b = new BIGNUM **[n];
                EC_POINT ***B = new EC_POINT **[n];

                unsigned char **x = new unsigned char *[n + 1];
                unsigned char **X = new unsigned char *[n + 1];

                unsigned char **str_s = new unsigned char *[n + 1];
                unsigned char **enc_s = new unsigned char *[n + 1];

                unsigned char ***str_b = new unsigned char **[n];
                unsigned char ***enc_b = new unsigned char **[n];
                unsigned char ***str_B = new unsigned char **[n];

                for (int i = 0; i < n + 1; i++)
                {
                    x[i] = new unsigned char[Zp_SPACE];
                    X[i] = new unsigned char[G_SPACE];
                    s[i] = BN_new();

                    memset(x[i], 0x00, Zp_SPACE);
                    memset(X[i], 0x00, G_SPACE);

                    str_s[i] = new unsigned char[STR_LENGTH];
                    enc_s[i] = new unsigned char[CIPHERTEXT_SPACE];
                }

                polinomial_generator(t, n, lambda, x, X);

                for (int i = 0; i < n; i++)
                {

                    P[i] = new PARTIES(t, n, i + 1, x[i + 1], X, lambda);

                    b[i] = new BIGNUM *[n];
                    str_b[i] = new unsigned char *[n];
                    enc_b[i] = new unsigned char *[n];

                    B[i] = new EC_POINT *[n];
                    str_B[i] = new unsigned char *[n];
                }

                // phase 1
                t0 = P[0]->get_time();
                for (int i = 1; i < t + 1; i++)
                {
                    for (int j = 1; j < t + 1; j++)
                    {
                        if (i == j)
                            continue;

                        b[i][j] = BN_new();
                        B[i][j] = EC_POINT_new(P[i]->curve);
                        str_b[i][j] = new unsigned char[STR_LENGTH];
                        enc_b[i][j] = new unsigned char[CIPHERTEXT_SPACE];
                        str_B[i][j] = new unsigned char[G_SPACE];

                        memset(str_b[i][j], 0x00, STR_LENGTH);
                        memset(enc_b[i][j], 0x00, CIPHERTEXT_SPACE);

                        if (!BN_rand_range(b[i][j], P[i]->order))
                            P[i]->handleErrors();

                        EC_POINT_mul(P[i]->curve, B[i][j], b[i][j], NULL, NULL, P[i]->bn_ctx);

                        strcpy((char *)str_b[i][j], BN_bn2hex(b[i][j]));
                        P[i]->AES256GCM_ENC(str_b[i][j], strlen((char *)str_b[i][j]), P[i]->key[j], P[i]->iv[j], enc_b[i][j]);

                        strcpy((char *)str_B[i][j], EC_POINT_point2hex(P[i]->curve, B[i][j], EC_GROUP_get_point_conversion_form(P[i]->curve), P[i]->bn_ctx));
                    }
                }
                t1 = P[0]->get_time();
                p1 += t1 - t0;

                // std::cout << "complete phase1" << std::endl;
                // phase 2
                t0 = P[0]->get_time();
                for (int i = 1; i < t + 1; i++)
                {
                    BIGNUM *li = BN_new();
                    li = P[i]->L(t + 1, i + 1, 1);

                    BN_mod_mul(s[i + 1], P[i]->si, li, P[i]->order, P[i]->bn_ctx);

                    for (int j = 1; j < t + 1; j++)
                    {

                        if (i == j)
                            continue;

                        BIGNUM *bji = BN_new();
                        EC_POINT *Bji = EC_POINT_new(P[i]->curve);
                        unsigned char *dec_bji = new unsigned char[STR_LENGTH];

                        memset(dec_bji, 0x00, STR_LENGTH);

                        P[i]->AES256GCM_DEC(enc_b[j][i], strlen((char *)enc_b[j][i]), P[i]->key[j], P[i]->iv[j], dec_bji);
                        // BN_hex2bn(&rij, (char *)dec_rij);

                        BN_copy(bji, b[j][i]);
                        EC_POINT_mul(P[i]->curve, Bji, bji, NULL, NULL, P[i]->bn_ctx); // Bji = bji G

                        if (EC_POINT_cmp(P[i]->curve, Bji, B[j][i], P[i]->bn_ctx))
                            P[i]->handleErrors();

                        BN_mod_add(s[i + 1], s[i + 1], b[i][j], P[i]->order, P[i]->bn_ctx);
                        BN_mod_sub(s[i + 1], s[i + 1], b[j][i], P[i]->order, P[i]->bn_ctx);

                        BN_free(bji);
                        EC_POINT_free(Bji);
                        delete[] dec_bji;
                    }
                    strcpy((char *)str_s[i + 1], BN_bn2hex(s[i + 1]));

                    P[i]->AES256GCM_ENC(str_s[i + 1], strlen((char *)str_s[i + 1]), P[i]->key[0], P[i]->iv[0], enc_s[i + 1]);
                }
                t1 = P[0]->get_time();
                p2 += t1 - t0;

                // std::cout << "complete phase2" << std::endl;

                // phase 3
                t0 = P[0]->get_time();
                for (int j = 1; j < t + 1; j++)
                {
                    unsigned char *dec_sj = new unsigned char[STR_LENGTH];
                    BIGNUM *sj = BN_new();
                    P[0]->AES256GCM_DEC(str_s[j + 1], strlen((char *)str_s[j + 1]), P[0]->key[j], P[1]->iv[j], dec_sj);
                    // BN_hex2bn(sj, dec_sj);
                    BN_copy(sj, s[j + 1]);
                    BN_mod_add(s[1], s[1], s[j + 1], P[0]->order, P[0]->bn_ctx);
                }

                // EC_POINT *cmp = EC_POINT_new(P[i]->curve);
                EC_POINT *cmp1 = EC_POINT_new(P[0]->curve);
                EC_POINT *cmp2 = EC_POINT_new(P[0]->curve);

                EC_POINT_mul(P[0]->curve, cmp1, s[1], NULL, NULL, P[0]->bn_ctx);

                EC_POINT_hex2point(P[0]->curve, (char *)X[1], cmp2, P[0]->bn_ctx);

                if (EC_POINT_cmp(P[0]->curve, cmp1, cmp2, P[0]->bn_ctx))
                    P[0]->handleErrors();

                t1 = P[0]->get_time();
                p3 += t1 - t0;

                // std::cout << "complete phase3" << std::endl;

                EC_POINT_free(cmp1);
                EC_POINT_free(cmp2);
            }

            ofstream File;
            string name = "../data/our-" + to_string(t) + "-" + to_string(n) + "-" + to_string(lambda) + "-" + to_string(TESTCNT) + ".txt";

            File.open(name);
            File << "t = " << t << ", n = " << n << ", lambda = " << lambda << ", TESTCNT = " << TESTCNT << "\n";
            File << "Phase 1 : " << p1 << "(s), " << p1 * 1000 << "(ms)"
                 << "\n";
            File << "Phase 2 : " << p2 << "(s), " << p2 * 1000 << "(ms)"
                 << "\n";
            File << "Phase 3 : " << p3 << "(s), " << p3 * 1000 << "(ms)"
                 << "\n";

            File.close();
        }
    }

    return 0;
}