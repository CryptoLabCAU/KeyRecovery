// g++ -o recovery recovery.cpp parties.cpp -lssl -lcrypto
// ./recovery -N 3 -P 1 -a 127.0.0.1,127.0.0.1,127.0.0.1 -p 12345
// ./recovery -N 3 -P 2 -a 127.0.0.1,127.0.0.1,127.0.0.1 -p 12345 -I ../data/p2.dat
// ./recovery -N 3 -P 3 -a 127.0.0.1,127.0.0.1,127.0.0.1 -p 12345 -I ../data/p3.dat

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

#define STR_LENGTH 1024
#define Zp_SPACE 256
#define G_SPACE 256
#define CIPHERTEXT_SPACE 256

void P1(PARTIES &p) // receive {si, Bij, Bji} from Pi
{
    double t0 = 0, t1 = 0;
    BIGNUM **s = new BIGNUM *[p.parties];
    EC_POINT **X = new EC_POINT *[p.parties];
    EC_POINT ***B = new EC_POINT **[p.parties - 1];

    for (int i = 0; i < p.parties; i++)
    {
        s[i] = BN_new();
        X[i] = EC_POINT_new(p.curve);
        if (i < p.parties - 1)
        {
            B[i] = new EC_POINT *[p.parties - 1];
            for (int j = 0; j < p.parties - 1; j++)
            {
                B[i][j] = EC_POINT_new(p.curve);
            }
        }
    }

    for (int i = 1; i < p.parties; i++) // receive Xi
    {
        int recv_len;
        char *str_Xi = new char[G_SPACE];

        memset(str_Xi, 0x00, G_SPACE);

        char *tmp = str_Xi;
        int len = G_SPACE;
        while (0 != (recv_len = recv(p.parties_sock[i], tmp, len, 0)))
        {
            int buf_len = strlen(str_Xi);

            if (buf_len < G_SPACE)
            {
                tmp += recv_len;
                len -= recv_len;
                continue;
            }
            else
                break;
        }

        EC_POINT_hex2point(p.curve, str_Xi, X[i], p.bn_ctx);

        delete[] str_Xi;
    }

    for (int i = 1; i < p.parties; i++) // receive [ENC(si) || Bijs || Bjis]
    {
        int recv_len, plen;
        int buf_len = CIPHERTEXT_SPACE + 2 * (p.parties - 2) * G_SPACE;
        int buf_offset = 0;

        char *str_si = new char[Zp_SPACE];
        char *str_cipher = new char[CIPHERTEXT_SPACE];
        char *buf = new char[buf_len];


        memset(str_si, 0x00, Zp_SPACE);
        memset(str_cipher, 0x00, CIPHERTEXT_SPACE);
        memset(buf, 0x00, buf_len);

        char *tmp = buf;
        int len = buf_len;
        while (0 != (recv_len = recv(p.parties_sock[i], tmp, len, 0)))
        {
            int tmp_len = strlen(buf);

            if (tmp_len < buf_len)
            {
                tmp += recv_len;
                len -= recv_len;
                continue;
            }
            else
                break;
        }

        memcpy(str_cipher, buf + buf_offset, CIPHERTEXT_SPACE);
        buf_offset += CIPHERTEXT_SPACE;

        int clen;
        // if ((clen = p.AES256GCM_DEC((unsigned char *)str_cipher, strlen(str_cipher), , p.tag[i], p.key[i], p.iv[i], (unsigned char *)str_si)) > 0)
        // {
        //     str_si[clen] = '\0';
        // }
        if ((clen = p.AES256GCM_DEC((unsigned char *)str_cipher, strlen(str_cipher), p.key[i], p.iv[i], (unsigned char *)str_si)) > 0)
        {
            str_si[clen] = '\0';
        }

        BN_hex2bn(&s[i], str_si);
        printf("receive from P%d\n", i + 1);
        printf("s%d : %s\n", i + 1, str_si);

        delete[] str_si;
        delete[] str_cipher;

        for (int j = 1; j < p.parties; j++) // Bij
        {
            if (i == j)
                continue;

            char *str_Bij = new char[G_SPACE];
            char *cmp = new char[G_SPACE];

            memcpy(str_Bij, buf + buf_offset, G_SPACE);
            buf_offset += G_SPACE;

            printf("B%d%d : %s\n", i + 1, j + 1, str_Bij);
            
            strcpy(cmp, EC_POINT_point2hex(p.curve, B[i - 1][j - 1], EC_GROUP_get_point_conversion_form(p.curve), p.bn_ctx));

            if (strcmp(cmp, "00") == 0) // empty
                EC_POINT_hex2point(p.curve, str_Bij, B[i - 1][j - 1], p.bn_ctx);
            else if (strcmp(cmp, str_Bij) != 0) // not match
            {
                printf("Bij is not eqaul Bji\n");
                p.handleErrors();
            }
            delete[] cmp;
            delete[] str_Bij;
        }
        for (int j = 1; j < p.parties; j++) // Bji
        {
            if (i == j)
                continue;

            char *str_Bji = new char[G_SPACE];
            char *cmp = new char[G_SPACE];

            memcpy(str_Bji, buf + buf_offset, G_SPACE);
            buf_offset += G_SPACE;
            
            printf("B%d%d : %s\n", j + 1, i + 1, str_Bji);
            
            strcpy(cmp, EC_POINT_point2hex(p.curve, B[j - 1][i - 1], EC_GROUP_get_point_conversion_form(p.curve), p.bn_ctx));
            

            if(strcmp(cmp, "00") == 0)  // empty
                EC_POINT_hex2point(p.curve, str_Bji, B[j - 1][i - 1], p.bn_ctx);
            else if(strcmp(cmp, str_Bji) != 0) // not match
            {
                printf("Bji is not eqaul Bij\n");
                p.handleErrors();
            }
                        
            
            delete[] cmp;
            delete[] str_Bji;
        }
        printf("\n");

    }

    for (int i = 1; i < p.parties; i++) // check wheter si * G == Li(1) * Xi + Bij - Bji
    {
        EC_POINT *tmp1 = EC_POINT_new(p.curve);
        EC_POINT *tmp2 = EC_POINT_new(p.curve);
        EC_POINT *Bji = EC_POINT_new(p.curve);

        if (!EC_POINT_mul(p.curve, tmp1, s[i], NULL, NULL, p.bn_ctx))
            p.handleErrors();

        if (!EC_POINT_mul(p.curve, tmp2, NULL, X[i], p.L(i + 1, 1), p.bn_ctx))
            p.handleErrors();

        for (int j = 1; j < p.parties; j++) // have to check this point.
        {
            if (i == j)
                continue;

            if (!EC_POINT_add(p.curve, tmp2, tmp2, B[i - 1][j - 1], p.bn_ctx))
                p.handleErrors();

            EC_POINT_copy(Bji, B[j - 1][i - 1]);
            EC_POINT_invert(p.curve, Bji, p.bn_ctx);

            if (!EC_POINT_add(p.curve, tmp2, tmp2, Bji, p.bn_ctx))
                p.handleErrors();
        }
        if (EC_POINT_cmp(p.curve, tmp1, tmp2, p.bn_ctx))
        {
            printf("si is not eqaul to Li(1)Xi + Bij - Bji\n");
            p.handleErrors();
        }

        EC_POINT_free(tmp1);
        EC_POINT_free(tmp2);
        EC_POINT_free(Bji);
    }

    // x1 = {si}
    char *str_s1 = new char[Zp_SPACE];
    for (int i = 1; i < p.parties; i++)
    {
        BN_mod_add(s[0], s[0], s[i], p.order, p.bn_ctx);
    }
    p.xi = s[0];
    strcpy(str_s1, BN_bn2hex(p.xi));

    printf("s1 : %s\n", str_s1);

    delete[] str_s1;
}

void Pi(PARTIES &p)
{

    double t0 = 0, t1 = 0;
    BIGNUM **bi = new BIGNUM *[p.parties]; // Pi sends bi to Pj
    BIGNUM **bj = new BIGNUM *[p.parties]; // Pi receives bj from Pj
    EC_POINT **Bi = new EC_POINT *[p.parties];
    EC_POINT **Bj = new EC_POINT *[p.parties];
    // send Xi to P1
    char *str_Xi = new char[G_SPACE];

    strcpy(str_Xi, EC_POINT_point2hex(p.curve, p.Xi, EC_GROUP_get_point_conversion_form(p.curve), p.bn_ctx));

    printf("X%d = %s\n",p.index, str_Xi);

    if (send(p.parties_sock[0], str_Xi, G_SPACE, 0) == -1)
        p.handleErrors();

    delete[] str_Xi;

    // send bij
    for (int i = 1; i < p.parties; i++)
    {
        if (i == p.index - 1)
            continue;

        int clen;
        char *str_bij = new char[Zp_SPACE];
        char *str_Bij = new char[G_SPACE];
        char *str_cipher = new char[CIPHERTEXT_SPACE];
        char *buf = new char[CIPHERTEXT_SPACE + G_SPACE];

        memset(str_bij, 0x00, Zp_SPACE);
        memset(str_Bij, 0x00, G_SPACE);
        memset(str_cipher, 0x00, CIPHERTEXT_SPACE);
        memset(buf, 0x00, CIPHERTEXT_SPACE + G_SPACE);

        bi[i] = BN_new();
        Bi[i] = EC_POINT_new(p.curve);

        if (!BN_rand_range(bi[i], p.order))
            p.handleErrors();

        if (!EC_POINT_mul(p.curve, Bi[i], bi[i], NULL, NULL, p.bn_ctx))
            p.handleErrors();

        strcpy(str_bij, BN_bn2hex(bi[i]));

        if ((clen = p.AES256GCM_ENC((unsigned char *)str_bij, strlen(str_bij), p.key[i], p.iv[i], (unsigned char *)str_cipher)) < 0)
        {
            printf("encryption fails\n");
            p.handleErrors();
        }

        strcpy(str_Bij, EC_POINT_point2hex(p.curve, Bi[i], EC_GROUP_get_point_conversion_form(p.curve), p.bn_ctx));

        memcpy(buf, str_cipher, CIPHERTEXT_SPACE);
        memcpy(buf + CIPHERTEXT_SPACE, str_Bij, G_SPACE);

        if (send(p.parties_sock[i], buf, CIPHERTEXT_SPACE + G_SPACE, 0) == -1) // (ENC(bij) || Bij) 전송
            p.handleErrors();

        printf("send to P%d\n", i + 1);
        printf("b%d%d : %s\n", p.index, i + 1, str_bij);
        printf("B%d%d : %s\n\n", p.index, i + 1, str_Bij);

        delete[] str_bij;
        delete[] str_Bij;
        delete[] str_cipher;
        delete[] buf;
    }
    
    
    // receive bji
    for (int i = 1; i < p.parties; i++)
    {
        if (i == p.index - 1)
            continue;

        int recv_len;
        int plen;
        char *str_bji = new char[Zp_SPACE];
        char *str_Bji = new char[G_SPACE];
        char *str_cipher = new char[CIPHERTEXT_SPACE];
        char *buf = new char[CIPHERTEXT_SPACE + G_SPACE];

        EC_POINT *Bji = EC_POINT_new(p.curve);

        memset(str_bji, 0x00, Zp_SPACE);
        memset(str_Bji, 0x00, G_SPACE);
        memset(str_cipher, 0x00, CIPHERTEXT_SPACE);
        memset(buf, 0x00, CIPHERTEXT_SPACE + G_SPACE);

        bj[i] = BN_new();
        Bj[i] = EC_POINT_new(p.curve);

        if ((recv_len = recv(p.parties_sock[i], buf, CIPHERTEXT_SPACE + G_SPACE, 0)) == -1)
            p.handleErrors();

        memcpy(str_cipher, buf, CIPHERTEXT_SPACE);
        memcpy(str_Bji, buf + CIPHERTEXT_SPACE, G_SPACE);

        if ((plen = p.AES256GCM_DEC((unsigned char *)str_cipher, strlen(str_cipher), p.key[i], p.iv[i], (unsigned char *)str_bji)) > 0) // check this point
        {
            str_bji[plen] = '\0';
        }

        BN_hex2bn(&bj[i], str_bji);

        EC_POINT_hex2point(p.curve, str_Bji, Bj[i], p.bn_ctx);
        // check wheter Bji = bji * G
        if (!EC_POINT_mul(p.curve, Bji, bj[i], NULL, NULL, p.bn_ctx))
            p.handleErrors();

        printf("receive from P%d\n", i + 1);
        printf("b%d%d : %s\n", i + 1, p.index, str_bji);
        printf("B%d%d : %s\n\n", i + 1, p.index, str_Bji);

        if (EC_POINT_cmp(p.curve, Bj[i], Bji, p.bn_ctx))
        {
            printf("Bji is not eqaul bji * G\n");
            p.handleErrors();
        }

        delete[] str_bji;
        delete[] str_Bji;
        delete[] str_cipher;
        delete[] buf;
    }

    printf("\n");
    // compute si

    BIGNUM *li = BN_new();
    BIGNUM *si = BN_new();

    li = p.L(p.pi, 1);

    BN_mod_mul(si, p.xi, li, p.order, p.bn_ctx);

    for (int i = 1; i < p.parties; i++)
    {
        if (i == p.index - 1)
            continue;

        BIGNUM *bij = BN_new();

        BN_mod_sub(bij, bi[i], bj[i], p.order, p.bn_ctx);
        BN_mod_add(si, si, bij, p.order, p.bn_ctx);

        BN_free(bij);
    }

    // send {si, {Bij}, {Bji}} to P1
    int buf_len = CIPHERTEXT_SPACE + 2 * (p.parties - 2) * G_SPACE;
    char *str_si = new char[Zp_SPACE];
    char *str_cipher = new char[CIPHERTEXT_SPACE];
    char *buf = new char[buf_len];
    int buf_offset = 0;

    memset(str_si, 0x00, Zp_SPACE);
    memset(str_cipher, 0x00, CIPHERTEXT_SPACE);
    memset(buf, 0x00, buf_len);

    strcpy(str_si, BN_bn2hex(si));

    int clen = 0;
    if ((clen = p.AES256GCM_ENC((unsigned char *)str_si, strlen(str_si), p.key[0], p.iv[0], (unsigned char *)str_cipher)) < 0)
    {
        printf("encryption fails\n");
        p.handleErrors();
    }

    memcpy(buf + buf_offset, str_cipher, CIPHERTEXT_SPACE);
    buf_offset += CIPHERTEXT_SPACE;

    for (int i = 1; i < p.parties; i++) // append Bij
    {
        if (i == p.index - 1)
            continue;

        memcpy(buf + buf_offset, EC_POINT_point2hex(p.curve, Bi[i], EC_GROUP_get_point_conversion_form(p.curve), p.bn_ctx), G_SPACE);
        buf_offset += G_SPACE;
    }

    for (int i = 1; i < p.parties; i++) // append Bji
    {
        if (i == p.index - 1)
            continue;

        memcpy(buf + buf_offset, EC_POINT_point2hex(p.curve, Bj[i], EC_GROUP_get_point_conversion_form(p.curve), p.bn_ctx), G_SPACE);
        buf_offset += G_SPACE;
    }

    if (send(p.parties_sock[0], buf, buf_len, 0) == -1) // [ENC(si) || Bijs || Bjis] 전송
        p.handleErrors();

    printf("send s%d\n%s\n", p.index, str_si);

    delete[] bi;
    delete[] bj;
    delete[] Bi;
    delete[] Bj;
    delete[] buf;
    delete[] str_si;
    delete[] str_cipher;
    BN_free(li);
    BN_free(si);
}

int main(int argc, char *argv[])
{
    PARTIES p(argc, argv);

    if (p.index == 1)
        P1(p);
    else
        Pi(p);
}