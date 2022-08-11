// g++ -o measure_algorithm measure_algorithm.cpp -lssl -lcrypto
#include <iostream>
#include <string>
#include <fstream>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <sys/time.h>

using namespace std;

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

double get_time(void)
{
    static struct timeval last_tv, tv;
    static int first = 1;
    static double res = 0;

    if (first)
    {
        gettimeofday(&last_tv, NULL);
        first = 0;
        return 0;
    }
    else
    {
        gettimeofday(&tv, NULL);
        res += tv.tv_sec - last_tv.tv_sec;
        res += (tv.tv_usec - last_tv.tv_usec) / 1000000.0;
        last_tv = tv;

        return res;
    }
}

int main(int argc, char *argv[])
{
    int curves[4] = {NID_secp160k1, NID_secp192k1, NID_secp224k1, NID_secp256k1};

    for (int index = 0; index < 4; index++)
    {

        double t0 = 0, t1 = 0;
        double bn_add_time = 0, bn_sub_time = 0, bn_rand_time = 0, bn_mul_time = 0;
        double EC_add_time = 0, EC_mul_time = 0, EC_compare_true = 0, EC_compare_false = 0;

        for (int cnt = 0; cnt < ; cnt++)
        {
            EC_GROUP *gruop;
            BN_CTX *ctx = BN_CTX_new();
            BIGNUM *order = BN_new();
            BIGNUM *num1 = BN_new();
            BIGNUM *num2 = BN_new();
            BIGNUM *bn_add = BN_new();
            BIGNUM *bn_sub = BN_new();
            BIGNUM *bn_mul = BN_new();
            EC_POINT *point1, *point2;
            EC_POINT *EC_add;
            EC_POINT *EC_mul;
            // const EC_POINT *generator;

            if (NULL == (gruop = EC_GROUP_new_by_curve_name(curves[index])))
                handleErrors();

            if (EC_GROUP_get_order(gruop, order, ctx) == 0)
                handleErrors();

            EC_add = EC_POINT_new(gruop);
            EC_mul = EC_POINT_new(gruop);
            point1 = EC_POINT_new(gruop);
            point2 = EC_POINT_new(gruop);
            t0 = get_time();
            if (BN_rand_range(num1, order) == 0)
                handleErrors();
            t1 = get_time();
            bn_rand_time += t1 - t0;

            if (BN_rand_range(num2, order) == 0)
                handleErrors();

            // if ((generator = EC_GROUP_get0_generator(gruop)) == NULL)
            //     handleErrors();

            t0 = get_time();
            BN_mod_add(bn_add, num1, num2, order, ctx);
            t1 = get_time();
            bn_add_time += t1 - t0;

            t0 = get_time();
            BN_mod_sub(bn_sub, num1, num2, order, ctx);
            t1 = get_time();
            bn_sub_time += t1 - t0;

            t0 = get_time();
            BN_mod_mul(bn_mul, num1, num2, order, ctx);
            t1 = get_time();
            bn_mul_time += t1 - t0;

            if (!EC_POINT_mul(gruop, point1, num1, NULL, NULL, ctx)) // num1 * g
                handleErrors();

            t0 = get_time();
            if (!EC_POINT_mul(gruop, point2, num2, NULL, NULL, ctx))
                handleErrors();
            t1 = get_time();
            EC_mul_time += t1 - t0;

            t0 = get_time();
            if (!EC_POINT_add(gruop, EC_add, point1, point2, ctx))
                handleErrors();
            t1 = get_time();
            EC_add_time += t1 - t0;

            t0 = get_time();
            if (EC_POINT_cmp(gruop, point1, point1, ctx))
                ;
            t1 = get_time();
            EC_compare_true += t1 - t0;

            t0 = get_time();
            if (EC_POINT_cmp(gruop, point1, point2, ctx))
                ;
            t1 = get_time();
            EC_compare_false += t1 - t0;

            // if (!EC_POINT_mul(gruop, EC_mul, num1, generator, num2, ctx)) // num1 * g + num2 * g
            //     handleErrors();

            BN_free(order);
            BN_free(num1);
            BN_free(num2);
            BN_free(bn_add);
            BN_free(bn_sub);
            BN_free(bn_mul);
            EC_POINT_free(point1);
            EC_POINT_free(point2);
            EC_POINT_free(EC_add);
            EC_POINT_free(EC_mul);
            EC_GROUP_free(gruop);
            BN_CTX_free(ctx);
        }
        if (index == 0)
            printf("SECP160K1\n");
        else if (index == 1)
            printf("SECP192K1\n");
        else if (index == 2)
            printf("SECP224K1\n");
        else if (index == 3)
            printf("SECP256K1\n");
        else
            ;

        // printf("bn_rand_time = %f\n", bn_rand_time);
        // printf("bn_add_time = %f\n", bn_add_time);
        // printf("bn_sub_time = %f\n", bn_sub_time);
        // printf("bn_mul_time = %f\n", bn_mul_time);
        // printf("EC_add_time = %f\n", EC_add_time);
        // printf("EC_mul_time = %f\n", EC_mul_time);
        // printf("EC_compare_true = %f\n", EC_compare_true);
        // printf("EC_compare_false = %f\n\n", EC_compare_false);
    }
    return 0;
}