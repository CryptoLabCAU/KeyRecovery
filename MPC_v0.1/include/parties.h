#ifndef __PARTIES_H__
#define __PARTIES_H__

#include <iostream>
#include <fstream>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <cstring>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define AES_256_KEY_LENGTH 32
#define AES_256_KEY_LENGTH_BITS 256
#define AES_256_IV_LENGTH 16
#define AES_256_GCM_IV_LENGTH 16
#define AES_256_GCM_AAD_LENGTH 16
#define AES_256_GCM_TAG_LENGTH 16

using namespace std;

#ifdef __cplusplus
extern "C"
{
#endif

    class PARTIES
    {
    public:
        BN_CTX *bn_ctx;
        EC_GROUP *curve;
        BIGNUM *order;  // q
        BIGNUM **coeff; // polynomial

        // BIGNUM *generator; // G
        BIGNUM *xi; // sharing x_i of the secret

        bool lflag, sflag;

        const EC_POINT *generator_point; // G
        EC_POINT *Xi;                    // x_i * G
        EC_POINT *X;

        // TCP/IP sockets
        int *parties_sock; // 자신의 인덱스는 server socket으로 설정.
        struct sockaddr_in *parties_addr;
        socklen_t *parties_addr_size;
        vector<string> str_addr;

        // AES keys
        unsigned char **key;
        unsigned char **iv;

        // filename;
        string infile;
        string outfile;

        // (t, n) - threshold or (t + 1) out of n
        int t, n, parties, pi;
        int index, port; // port = base port + index
        // constructors
        PARTIES();
        PARTIES(int num); // 불러오기
        PARTIES(int argc, char *argv[]);

        // destructor
        ~PARTIES();

        // functions
        void parse_option(int argc, char *argv[]);
        BIGNUM *computePij(int j);
        void initSocket();
        void handleErrors();
        int getparties();
        double get_time();
        const EC_GROUP *getgroup();
        void loadFile();
        void saveFile();
        BIGNUM *L(int i, int x);
        int AES256GCM_ENC(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                          unsigned char *iv, unsigned char *ciphertext);

        int AES256GCM_DEC(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                          unsigned char *iv, unsigned char *plaintext);
    };

#ifdef __cplusplus
}
#endif

#endif