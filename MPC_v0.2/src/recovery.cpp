// g++ -o recovery recovery.cpp parties.cpp -lssl -lcrypto

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
#define G_SPACE 512
#define CIPHERTEXT_SPACE 1024

void P1(PARTIES &p) // receive {si, Bij, Bji} from Pi
{
    double t0 = 0, t1 = 0, P3_network_time = 0, P3_decryption_time=0, P3_computation_time = 0;
    BIGNUM **s = new BIGNUM *[p.parties + 1];
    EC_POINT ***B = new EC_POINT **[p.parties - 1];
    EC_POINT *X1 = EC_POINT_new(p.curve);

    for (int i = 0; i <= p.parties; i++)
        s[i] = BN_new();

    for (int i = 1; i < p.parties; i++) // receive ENC(si)
    {
        int recv_len = 0;

        char *str_si = new char[Zp_SPACE];
        char *str_cipher = new char[CIPHERTEXT_SPACE];

        memset(str_si, 0x00, Zp_SPACE);
        memset(str_cipher, 0x00, CIPHERTEXT_SPACE);

        char *tmp = str_cipher;
        int len = CIPHERTEXT_SPACE;

        t0 = p.get_time();
        while (0 != (recv_len = recv(p.parties_sock[i], tmp, len, 0)))
        {
            int tmp_len = strlen(str_cipher);

            if (tmp_len < CIPHERTEXT_SPACE)
            {
                tmp += recv_len;
                len -= recv_len;
                continue;
            }
            else
                break;
        }

        t1 = p.get_time();
        P3_network_time += t1 - t0;

        int clen;
        t0 = p.get_time();
        if ((clen = p.AES256GCM_DEC((unsigned char *)str_cipher, strlen(str_cipher), p.key[i], p.iv[i], (unsigned char *)str_si)) > 0)
        {
            str_si[clen] = '\0';
        }
        t1 = p.get_time();

        P3_decryption_time += t1 - t0;

        BN_hex2bn(&s[i + 1], str_si);
        printf("receive from P%d\n", i + 1);
        printf("s%d : %s\n", i + 1, str_si);

        delete[] str_si;
        delete[] str_cipher;
    }
    printf("\n");
    // x1 = {si}
    t0 = p.get_time();
    for (int i = 2; i <= p.parties; i++)
    {
        BN_mod_add(s[1], s[1], s[i], p.order, p.bn_ctx);
    }

    if (!EC_POINT_mul(p.curve, X1, s[1], NULL, NULL, p.bn_ctx))
        p.handleErrors();


    if (EC_POINT_cmp(p.curve, X1, p.X[1], p.bn_ctx) != 0)
        p.handleErrors();
    else
    {
        p.xi = s[1];

        char *str_s1 = new char[Zp_SPACE];
        memset(str_s1, 0x00, Zp_SPACE);
        strcpy(str_s1, BN_bn2hex(p.xi));

        printf("recovery s1 : %s\n\n", str_s1);
        delete[] str_s1;
    }
    t1 = p.get_time();

    P3_computation_time += t1 - t0;
    printf("Phase 3\n");
    printf("Network time = %f\n", P3_network_time);
    printf("Decryption time = %f\n", P3_decryption_time);
    printf("computation time = %f\n", P3_computation_time);
}

void Pi(PARTIES &p)
{

    double t0 = 0, t1 = 0;
    double phase1_send_time = 0, phase1_encryption_time = 0, phase1_computation_time = 0;
    double phase2_send_time = 0, phase2_recv_time = 0, phase2_encryption_time = 0, phase2_verification_time = 0, phase2_decryption_time = 0, phase2_computation_time = 0;
    BIGNUM **bi = new BIGNUM *[p.parties]; // Pi sends bi to Pj
    BIGNUM **bj = new BIGNUM *[p.parties]; // Pi receives bj from Pj
    EC_POINT **Bi = new EC_POINT *[p.parties];
    EC_POINT **Bj = new EC_POINT *[p.parties];
    // send Xi to P1;

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

        
        t0 = p.get_time();
        if (!BN_rand_range(bi[i], p.order))
            p.handleErrors();

        if (!EC_POINT_mul(p.curve, Bi[i], bi[i], NULL, NULL, p.bn_ctx))
            p.handleErrors();

        t1 = p.get_time();
        phase1_computation_time += t1 - t0;

        t0 = p.get_time();
        strcpy(str_bij, BN_bn2hex(bi[i]));
        if ((clen = p.AES256GCM_ENC((unsigned char *)str_bij, strlen(str_bij), p.key[i], p.iv[i], (unsigned char *)str_cipher)) < 0)
        {
            printf("encryption fails\n");
            p.handleErrors();
        }

        t1 = p.get_time();
        phase1_encryption_time += t1 - t0;

        t0 = p.get_time();
        strcpy(str_Bij, EC_POINT_point2hex(p.curve, Bi[i], EC_GROUP_get_point_conversion_form(p.curve), p.bn_ctx));
        memcpy(buf, str_cipher, CIPHERTEXT_SPACE);
        memcpy(buf + CIPHERTEXT_SPACE, str_Bij, G_SPACE);
        
        if (send(p.parties_sock[i], buf, CIPHERTEXT_SPACE + G_SPACE, 0) == -1) // (ENC(bij) || Bij) 전송
            p.handleErrors();

        t1 = p.get_time();
        phase1_send_time += t1 - t0;

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

        t0 = p.get_time();
        if ((recv_len = recv(p.parties_sock[i], buf, CIPHERTEXT_SPACE + G_SPACE, 0)) == -1)
            p.handleErrors();
        t1 = p.get_time();
        phase2_recv_time += t1 - t0;

        memcpy(str_cipher, buf, CIPHERTEXT_SPACE);
        memcpy(str_Bji, buf + CIPHERTEXT_SPACE, G_SPACE);

        t0 = p.get_time();
        if ((plen = p.AES256GCM_DEC((unsigned char *)str_cipher, strlen(str_cipher), p.key[i], p.iv[i], (unsigned char *)str_bji)) > 0) // check this point
        {
            str_bji[plen] = '\0';
        }

        t1 = p.get_time();
        phase2_decryption_time += t1 - t0;
        BN_hex2bn(&bj[i], str_bji);

        t0 = p.get_time();
        EC_POINT_hex2point(p.curve, str_Bji, Bj[i], p.bn_ctx);
        // check wheter Bji = bji * G
        if (!EC_POINT_mul(p.curve, Bji, bj[i], NULL, NULL, p.bn_ctx))
            p.handleErrors();

        if (EC_POINT_cmp(p.curve, Bj[i], Bji, p.bn_ctx))
        {
            printf("Bji is not eqaul bji * G\n");
            p.handleErrors();
        }
        
        t1 = p.get_time();
        phase2_verification_time += t1 - t0;

        
        printf("receive from P%d\n", i + 1);
        printf("b%d%d : %s\n", i + 1, p.index, str_bji);
        printf("B%d%d : %s\n\n", i + 1, p.index, str_Bji);


        delete[] str_bji;
        delete[] str_Bji;
        delete[] str_cipher;
        delete[] buf;
    }

    // compute si

    t0 = p.get_time();
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
    t1 = p.get_time();
    phase2_computation_time += t1 - t0;

    // send {si, {Bij}, {Bji}} to P1
    char *str_si = new char[Zp_SPACE];
    char *str_cipher = new char[CIPHERTEXT_SPACE];

    memset(str_si, 0x00, Zp_SPACE);
    memset(str_cipher, 0x00, CIPHERTEXT_SPACE);

    strcpy(str_si, BN_bn2hex(si));

    
    t0 = p.get_time();
    int clen = 0;
    if ((clen = p.AES256GCM_ENC((unsigned char *)str_si, strlen(str_si), p.key[0], p.iv[0], (unsigned char *)str_cipher)) < 0)
    {
        printf("encryption fails\n");
        p.handleErrors();
    }
    t1 = p.get_time();
    phase2_encryption_time += t1 - t0;

    t0 = p.get_time();
    if (send(p.parties_sock[0], str_cipher, CIPHERTEXT_SPACE, 0) == -1) // ENC(si) 전송
        p.handleErrors();
    t1 = p.get_time();
    phase2_send_time += t1 - t0;

    printf("send s%d\n%s\n", p.index, str_si);

    printf("P%d\nphase 1\n", p.index);
    printf("Computation time = %f\n", phase1_computation_time);
    printf("Encrtyption time = %f\n", phase1_encryption_time);
    printf("Send time = %f\n\n", phase1_send_time);


    printf("phase 2\n");
    printf("recv time = %f\n", phase2_recv_time);
    printf("decryption time = %f\n", phase2_decryption_time);
    printf("Computation time = %f\n", phase2_computation_time);
    printf("Encrtyption time = %f\n", phase2_encryption_time);
    printf("Send time = %f\n", phase2_send_time);

    delete[] bi;
    delete[] bj;
    delete[] Bi;
    delete[] Bj;
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