#include <iostream>
#include <fstream>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
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

class PARTIES
{
public:
    BN_CTX *bn_ctx;
    EC_GROUP *curve;
    BIGNUM *order;  // q
    BIGNUM **coeff; // polynomial

    // BIGNUM *generator; // G
    BIGNUM *si; // sharing x_i of the secret

    bool lflag, sflag;

    const EC_POINT *G; // G
    EC_POINT **X;      // s_i * G

    // AES keys
    unsigned char **key;
    unsigned char **iv;

    // filename;
    string infile;
    string outfile;

    // (t, n) - threshold or (t + 1) out of n
    int t, n, index;
    int lambda;

    // constructors
    PARTIES();
    PARTIES(int _t, int _n, int _index, unsigned char *_si, unsigned char **_X, int _lambda);

    // destructor
    ~PARTIES();

    // functions
    void handleErrors();

    double get_time();

    void loadFile();
    void saveFile();

    unsigned char *synckeygen(int i, int j, unsigned char *nounce);
    unsigned char *syncivgen(int i, int j, unsigned char *nounce);

    BIGNUM *L(int Q, int i, int x);
    int AES256GCM_ENC(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                      unsigned char *iv, unsigned char *ciphertext);

    int AES256GCM_DEC(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                      unsigned char *iv, unsigned char *plaintext);
    void ZK_prove(unsigned char *_w, unsigned char *_R, unsigned char *_s);
    bool ZK_verify(unsigned char *_W, unsigned char *_R, unsigned char *_s);
    void Commitment(unsigned char *_a, unsigned char *com);
};