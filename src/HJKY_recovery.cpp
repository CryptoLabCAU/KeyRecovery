#include "parties.hpp"
#include "utils.hpp"
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <openssl/aes.h>
#include <fstream>

#define STR_LENGTH 1024
#define Zp_SPACE 256
#define G_SPACE 512
#define CIPHERTEXT_SPACE 1024

#define TESTCNT 1


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

                BIGNUM ***coeff_r = new BIGNUM **[n];
                BIGNUM ***r = new BIGNUM **[n];
                BIGNUM **a = new BIGNUM *[n];

                unsigned char **x = new unsigned char *[n + 1];
                unsigned char **X = new unsigned char *[n + 1];

                unsigned char ***comr = new unsigned char **[n];

                unsigned char ***str_r = new unsigned char **[n];
                unsigned char ***enc_r = new unsigned char **[n];
                unsigned char **str_a = new unsigned char *[n];
                unsigned char **enc_a = new unsigned char *[n];

                for (int i = 0; i < n + 1; i++)
                {
                    x[i] = new unsigned char[Zp_SPACE];
                    X[i] = new unsigned char[G_SPACE];

                    memset(x[i], 0x00, Zp_SPACE);
                    memset(X[i], 0x00, G_SPACE);
                }

                polinomial_generator(t, n, lambda, x, X);

                for (int i = 0; i < n; i++)
                {
                    P[i] = new PARTIES(t, n, i + 1, x[i + 1], X, lambda);
                    coeff_r[i] = new BIGNUM *[t];
                    r[i] = new BIGNUM *[n];
                    a[i] = BN_new();

                    comr[i] = new unsigned char *[t];
                    str_r[i] = new unsigned char *[n];
                    enc_r[i] = new unsigned char *[n];

                    str_a[i] = new unsigned char[STR_LENGTH];
                    enc_a[i] = new unsigned char[CIPHERTEXT_SPACE];
                }
                // phase 1
                t0 = P[0]->get_time();
                for (int i = 1; i < n; i++)
                {
                    for (int j = 0; j < t; j++)
                    {
                        coeff_r[i][j] = BN_new();
                        comr[i][j] = new unsigned char[G_SPACE];

                        memset(comr[i][j], 0x00, G_SPACE);
                    }

                    for (int j = 1; j < t; j++)
                    {
                        if (!BN_rand_range(coeff_r[i][j], P[i]->order))
                            P[i]->handleErrors();

                        BN_mod_sub(coeff_r[i][0], coeff_r[i][0], coeff_r[i][j], P[i]->order, P[i]->bn_ctx);
                        P[i]->Commitment((unsigned char *)BN_bn2hex(coeff_r[i][j]), comr[i][j]);
                    }

                    P[i]->Commitment((unsigned char *)BN_bn2hex(coeff_r[i][0]), comr[i][0]);

                    for (int j = 1; j < t + 1; j++)
                    {
                        BIGNUM *index = BN_new();
                        r[i][j] = BN_new();
                        str_r[i][j] = new unsigned char[STR_LENGTH];
                        enc_r[i][j] = new unsigned char[CIPHERTEXT_SPACE];

                        memset(str_r[i][j], 0x00, STR_LENGTH);
                        memset(enc_r[i][j], 0x00, CIPHERTEXT_SPACE);

                        BN_dec2bn(&index, to_string(j + 1).c_str());

                        for (int coeff = t - 1; coeff >= 0; coeff--) // P_cnt(i)
                        {
                            BN_mod_mul(r[i][j], r[i][j], index, P[i]->order, P[i]->bn_ctx);
                            BN_mod_add(r[i][j], r[i][j], coeff_r[i][coeff], P[i]->order, P[i]->bn_ctx);
                        }
                        if (i != j)
                        {
                            strcpy((char *)str_r[i][j], BN_bn2hex(r[i][j]));
                            P[i]->AES256GCM_ENC(str_r[i][j], strlen((char *)str_r[i][j]), P[i]->key[j], P[i]->iv[j], enc_r[i][j]);
                        }

                        BN_free(index);
                    }
                }
                t1 = P[0]->get_time();
                p1 += t1 - t0;

                // phase 2
                // std::cout << "complete phase1" << std::endl;
                t0 = P[0]->get_time();
                for (int i = 1; i < t + 1; i++)
                {

                    BIGNUM *index = BN_new();
                    BN_dec2bn(&index, to_string(i + 1).c_str());

                    // (b)
                    for (int j = 1; j < t + 1; j++)
                    {
                        unsigned char *dec_rij = new unsigned char[1024];
                        BIGNUM *rji = BN_new();

                        EC_POINT *cmp1 = EC_POINT_new(P[i]->curve);
                        EC_POINT *cmp2 = EC_POINT_new(P[i]->curve);

                        memset(dec_rij, 0x00, 1024);

                        if (i != j) // decryption
                        {

                            P[i]->AES256GCM_DEC(enc_r[j][i], strlen((char *)enc_r[j][i]), P[i]->key[j], P[i]->iv[j], dec_rij);
                            BN_copy(rji, r[j][i]);

                            EC_POINT_mul(P[i]->curve, cmp1, rji, NULL, NULL, P[i]->bn_ctx);

                            // verification

                            BIGNUM *tmp1 = BN_new();          // i^cnt
                            for (int cnt = 0; cnt < t; cnt++) // coeff
                            {

                                EC_POINT *com = EC_POINT_new(P[i]->curve);
                                EC_POINT *tmp2 = EC_POINT_new(P[i]->curve); // i^cnt * rjcnt * G

                                if (cnt == 0)
                                    BN_one(tmp1);
                                else if (cnt == 1)
                                    BN_copy(tmp1, index);
                                else
                                    BN_mod_mul(tmp1, tmp1, index, P[i]->order, P[i]->bn_ctx);

                                EC_POINT_hex2point(P[i]->curve, (char *)comr[j][cnt], com, P[i]->bn_ctx);

                                EC_POINT_mul(P[i]->curve, tmp2, NULL, com, tmp1, P[i]->bn_ctx);
                                EC_POINT_add(P[i]->curve, cmp2, cmp2, tmp2, P[i]->bn_ctx);

                                EC_POINT_free(com);
                                EC_POINT_free(tmp2);
                            }

                            if (EC_POINT_cmp(P[i]->curve, cmp1, cmp2, P[i]->bn_ctx))
                                P[i]->handleErrors();

                            BN_free(tmp1);
                        }
                        else
                            BN_copy(rji, r[i][j]);
                        // (d)

                        BN_mod_add(a[i], a[i], rji, P[i]->order, P[i]->bn_ctx);

                        BN_free(rji);

                        delete[] dec_rij;
                    }

                    BN_mod_add(a[i], a[i], P[i]->si, P[i]->order, P[i]->bn_ctx);
                    strcpy((char *)str_a[i], BN_bn2hex(a[i]));
                    P[i]->AES256GCM_ENC(str_a[i], strlen((char *)str_a[i]), P[i]->key[0], P[i]->iv[0], enc_a[i]);

                    BN_free(index);
                }
                t1 = P[0]->get_time();
                p2 += t1 - t0;

                // std::cout << "complete phase2" << std::endl;

                // phase 3
                t0 = P[0]->get_time();
                for (int j = 1; j < t + 1; j++)
                {
                    BIGNUM *li = BN_new();
                    BIGNUM *tmp = BN_new();
                    li = P[0]->L(t + 1, j + 1, 1);

                    BN_mod_mul(tmp, li, a[j], P[0]->order, P[0]->bn_ctx);
                    BN_mod_add(a[0], a[0], tmp, P[0]->order, P[0]->bn_ctx);
                }
                P[0]->si = a[0];
                EC_POINT *cmp1 = EC_POINT_new(P[0]->curve);
                EC_POINT_mul(P[0]->curve, cmp1, a[0], NULL, NULL, P[0]->bn_ctx);

                EC_POINT *cmp2 = EC_POINT_new(P[0]->curve);
                EC_POINT_hex2point(P[0]->curve, (char *)X[1], cmp2, P[0]->bn_ctx);

                if (EC_POINT_cmp(P[0]->curve, cmp1, cmp2, P[0]->bn_ctx))
                    P[0]->handleErrors();

                t1 = P[0]->get_time();
                p3 += t1 - t0;

                // std::cout << "complete phase3" << std::endl;
            }
            // printf("Phase 1 : %f(s) , %f(ms)\n", p1, p1 * 1000);

            // printf("Phase 2 : %f(s) , %f(ms)\n", p2, p2 * 1000);

            // printf("Phase 3 : %f(s) , %f(ms)\n", p3, p3 * 1000);

            ofstream File;
            string name = "../data/HJKY-" + to_string(t) + "-" + to_string(n) + "-" + to_string(lambda) + "-" + to_string(TESTCNT) + ".txt";

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