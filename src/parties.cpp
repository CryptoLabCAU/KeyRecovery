#include "parties.hpp"

PARTIES::PARTIES()
{
    this->t = 2;
    this->n = 3;
    this->bn_ctx = BN_CTX_new();
    this->order = BN_new();
    this->si = BN_new();

    if (NULL == (curve = EC_GROUP_new_by_curve_name(NID_secp256k1)))
        handleErrors();

    if (EC_GROUP_get_order(curve, order, bn_ctx) == 0) // return 1 on success and 0 if an error occurred
        handleErrors();

    if ((G = EC_GROUP_get0_generator(curve)) == NULL)
        handleErrors();
}

PARTIES::PARTIES(int _t, int _n, int _index, unsigned char *_si, unsigned char **_X, int _lambda)
{
    this->t = _t;
    this->n = _n;
    this->index = _index;
    this->lambda = _lambda;

    X = new EC_POINT *[n + 1]; // X + Xis

    this->bn_ctx = BN_CTX_new();
    this->order = BN_new();
    this->si = BN_new();

    key = new unsigned char *[n];
    iv = new unsigned char *[n];

    for (int i = 0; i < n; i++)
    {
        key[i] = new unsigned char[AES_256_KEY_LENGTH];
        iv[i] = new unsigned char[AES_256_IV_LENGTH];

        memset(key[i], 0x00, AES_256_KEY_LENGTH);
        memset(iv[i], 0x00, AES_256_IV_LENGTH);

        strcpy((char *)key[i], (char *)synckeygen(index, i + 1, (unsigned char *)"key_nounce"));
        strcpy((char *)iv[i], (char *)syncivgen(index, i + 1, (unsigned char *)"iv_nounce"));
    }

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

    BN_hex2bn(&si, (const char *)_si);

    X = new EC_POINT *[n + 1];
    for (int i = 0; i < n + 1; i++)
    {
        X[i] = EC_POINT_new(this->curve);
        EC_POINT_hex2point(curve, (char *)_X[i], X[i], bn_ctx);
    }
}

PARTIES::~PARTIES()
{
    for (int i = 0; i < n; i++)
    {
        delete[] key[i];
        delete[] iv[i];
    }

    delete[] key;
    delete[] iv;
}

void PARTIES::handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char *PARTIES::synckeygen(int i, int j, unsigned char *nounce)
{
    string strkey;
    unsigned char *key = new unsigned char[AES_256_KEY_LENGTH];
    memset(key, 0x00, AES_256_KEY_LENGTH);
    if (i > j)
        strkey = to_string(i) + to_string(j);
    else
        strkey = to_string(j) + to_string(i);

    strkey += static_cast<std::string>(reinterpret_cast<const char *>(nounce));

    SHA256((const unsigned char *)strkey.c_str(), strkey.size(), key);

    return key;
}

unsigned char *PARTIES::syncivgen(int i, int j, unsigned char *nounce)
{
    string striv;
    unsigned char *iv = new unsigned char[AES_256_IV_LENGTH];
    memset(iv, 0x00, AES_256_IV_LENGTH);
    if (i > j)
        striv = to_string(i) + to_string(j);
    else
        striv = to_string(j) + to_string(i);

    striv += static_cast<std::string>(reinterpret_cast<const char *>(nounce));

    MD5((const unsigned char *)striv.c_str(), striv.size(), iv);

    return iv;
}

// void PARTIES::saveFile()
// {
//     fstream fs;
//     fs.open(outfile);

//     fs << t << n << index << "\n";

//     for (int i = 0; i < t + 1; i++)
//     {
//         char *buf = new char[256];

//         memset(buf, 0x00, 256);
//         strcpy(buf, BN_bn2hex(coeff[i]));

//         fs << buf << "\n";
//         delete[] buf;
//     }

//     fs.close();
//     // output xi
//     // output t n
//     // output Xi
//     // output coefficients
//     // output index
// }

BIGNUM *PARTIES::L(int Q, int i, int x)
{
    BIGNUM *res = BN_new();
    BIGNUM *bnx = BN_new();
    BIGNUM *bni = BN_new();

    BN_dec2bn(&bnx, std::to_string(x).c_str());
    BN_dec2bn(&bni, std::to_string(i).c_str());
    BN_dec2bn(&res, std::to_string(1).c_str());

    for (int j = 2; j <= Q; j++)
    {
        if (j == i)
            continue;

        BIGNUM *bnj = BN_new();
        BIGNUM *tmp1 = BN_new();
        BIGNUM *tmp2 = BN_new();
        BIGNUM *tmpres = BN_new();

        BN_dec2bn(&bnj, std::to_string(j).c_str());
        BN_mod_sub(tmp1, bnx, bnj, order, bn_ctx); // x - j
        BN_mod_sub(tmp2, bni, bnj, order, bn_ctx); // i - j

        BN_mod_inverse(tmp2, tmp2, order, bn_ctx);     // (i - j)^{-1}
        BN_mod_mul(tmpres, tmp1, tmp2, order, bn_ctx); // tempres = (x - j)(i - j)^{-1}
        BN_mod_mul(res, res, tmpres, order, bn_ctx);   // res *= tmpres

        BN_free(bnj);
        BN_free(tmp1);
        BN_free(tmp2);
    }

    BN_free(bni);
    BN_free(bnx);

    return res;
}

int PARTIES::AES256GCM_ENC(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
                           unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len = 0, ciphertext_len = 0;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        handleErrors();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    // if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    // 	handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    /* encrypt in block lengths of 16 bytes */
    while (ciphertext_len <= plaintext_len - 16)
    {
        if (1 != EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext + ciphertext_len, 16))
            handleErrors();
        ciphertext_len += len;
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext + ciphertext_len, plaintext_len - ciphertext_len))
        handleErrors();
    ciphertext_len += len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    // if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_LENGTH, tag))
    //     handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int PARTIES::AES256GCM_DEC(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
                           unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    // if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    // 	handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    while (plaintext_len <= ciphertext_len - 16)
    {
        if (1 != EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &len, ciphertext + plaintext_len, 16))
            handleErrors();
        plaintext_len += len;
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &len, ciphertext + plaintext_len, ciphertext_len - plaintext_len))
        handleErrors();
    plaintext_len += len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    // if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    //     handleErrors();

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}

double PARTIES::get_time(void)
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

void PARTIES::ZK_prove(unsigned char *_w, unsigned char *_R, unsigned char *_s)
{
    BIGNUM *r = BN_new();
    BIGNUM *w = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *e = BN_new();

    EC_POINT *R = EC_POINT_new(curve);
    EC_POINT *W = EC_POINT_new(curve);

    unsigned char *buf = new unsigned char[512];
    unsigned char *strR = new unsigned char[256];
    unsigned char *strX = new unsigned char[256];
    unsigned char *hash = new unsigned char[SHA256_DIGEST_LENGTH];

    memset(strR, 0x00, 256);
    memset(strX, 0x00, 256);
    memset(buf, 0x00, 512);
    memset(hash, 0x00, SHA256_DIGEST_LENGTH);


    if (!BN_rand_range(r, order))
        handleErrors();

    BN_hex2bn(&w, (const char *)_w);

    EC_POINT_mul(curve, W, w, NULL, NULL, bn_ctx);
    EC_POINT_mul(curve, R, r, NULL, NULL, bn_ctx);

    strcpy((char *)strR, EC_POINT_point2hex(curve, R, EC_GROUP_get_point_conversion_form(curve), bn_ctx));
    strcpy((char *)strX, EC_POINT_point2hex(curve, W, EC_GROUP_get_point_conversion_form(curve), bn_ctx));

    // strcpy((char *)buf, (char *)strR);
    // strcat((char *)buf, (char *)strX);
    memcpy(buf, strR, 256);
    memcpy(buf + 256, strX, 256);

    SHA256(buf, 512, hash);
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, e);

    BN_mod_mul(s, e, w, order, bn_ctx);
    BN_mod_add(s, r, s, order, bn_ctx);
    strcpy((char *)_s, BN_bn2hex(s));
    strcpy((char *)_R, (char *)strR);

    BN_free(r);
    BN_free(w);
    BN_free(s);
    BN_free(e);

    EC_POINT_free(R);
    EC_POINT_free(W);
}
bool PARTIES::ZK_verify(unsigned char *_W, unsigned char *_R, unsigned char *_s)
{
    BIGNUM *s = BN_new();
    BIGNUM *e = BN_new();

    EC_POINT *W = EC_POINT_new(curve);
    EC_POINT *R = EC_POINT_new(curve);
    EC_POINT *cmp1 = EC_POINT_new(curve);
    EC_POINT *cmp2 = EC_POINT_new(curve);

    unsigned char *buf = new unsigned char[512];
    unsigned char *strR = new unsigned char[256];
    unsigned char *strX = new unsigned char[256];
    unsigned char *hash = new unsigned char[SHA256_DIGEST_LENGTH];

    memset(strR, 0x00, 256);
    memset(strX, 0x00, 256);
    memset(buf, 0x00, 512);
    memset(hash, 0x00, SHA256_DIGEST_LENGTH);

    strcpy((char *)strR, EC_POINT_point2hex(curve, R, EC_GROUP_get_point_conversion_form(curve), bn_ctx));
    strcpy((char *)strX, EC_POINT_point2hex(curve, W, EC_GROUP_get_point_conversion_form(curve), bn_ctx));

    strcpy((char *)buf, (char *)strR);
    strcat((char *)buf, (char *)strX);

    SHA256(buf, strlen((char *)buf), hash);
    BN_bin2bn(hash, 256, e);

    BN_hex2bn(&s, (char *)_s);

    EC_POINT_mul(curve, cmp1, s, NULL, NULL, bn_ctx); // cmp1 = sG
    EC_POINT_mul(curve, cmp2, NULL, W, e, bn_ctx);    // cmp2 = eW
    EC_POINT_add(curve, cmp2, cmp2, R, bn_ctx);       // cmp2 = ew + R

    if (!EC_POINT_cmp(curve, cmp1, cmp2, bn_ctx))
        return true;
    else
        return false;
}
void PARTIES::Commitment(unsigned char *_a, unsigned char *_com)
{
    BIGNUM *a = BN_new();
    EC_POINT *com = EC_POINT_new(curve);

    BN_hex2bn(&a, (char *)_a);
    EC_POINT_mul(curve, com, a, NULL, NULL, bn_ctx); // com = aG
    strcpy((char *)_com, EC_POINT_point2hex(curve, com, EC_GROUP_get_point_conversion_form(curve), bn_ctx));
}
