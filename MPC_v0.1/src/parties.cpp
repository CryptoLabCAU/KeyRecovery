#include "../include/parties.h"

PARTIES::PARTIES()
{
    this->bn_ctx = BN_CTX_new();
    this->order = BN_new();
    this->xi = BN_new();
    infile = "";
    outfile = "";

    if (NULL == (curve = EC_GROUP_new_by_curve_name(NID_secp256k1)))
        handleErrors();

    if (EC_GROUP_get_order(curve, order, bn_ctx) == 0) // return 1 on success and 0 if an error occurred
        handleErrors();

    if ((generator_point = EC_GROUP_get0_generator(curve)) == NULL)
        handleErrors();

    // this->coeff = new BIGNUM *[t + 1];

    // for (int i = 0; i <= t; i++)
    // {
    //     coeff[i] = BN_new();
    //     if(BN_rand_range(coeff[i], order) == 0)
    //         handleErrors();
    // }
}

PARTIES::PARTIES(int argc, char *argv[])
{
    lflag = false;
    sflag = false;
    parse_option(argc, argv);

    this->bn_ctx = BN_CTX_new();
    this->order = BN_new();
    this->xi = BN_new();
    

    key = new unsigned char *[parties];
    iv = new unsigned char *[parties];

    for (int i = 0; i < parties; i++)
    {
        key[i] = new unsigned char[AES_256_KEY_LENGTH];
        iv[i] = new unsigned char[AES_256_IV_LENGTH];

        memset(key[i], 0x00, AES_256_KEY_LENGTH);
        memset(iv[i], 0x00, AES_256_IV_LENGTH);

        strcpy((char *)key[i], "keykeykeykey");
        strcpy((char *)iv[i], "iviviviviviv");
    }


    


    if (NULL == (curve = EC_GROUP_new_by_curve_name(NID_secp256k1)))
        handleErrors();

    if (EC_GROUP_get_order(curve, order, bn_ctx) == 0) // return 1 on success and 0 if an error occurred
        handleErrors();

    if ((generator_point = EC_GROUP_get0_generator(curve)) == NULL)
        handleErrors();
    
    this->Xi = EC_POINT_new(this->curve);

    // if (!BN_rand_range(this->xi, this->order))
    //     handleErrors();

    // BN_dec2bn(&(this->xi), to_string(15 + 3 * index).c_str());
    // printf("xi = %d\n", 15 + 3 * index);
    if (lflag == true)
        loadFile();

    initSocket();
}

PARTIES::~PARTIES()
{
    if (sflag)
        saveFile();

    EC_GROUP_free(curve);
    BN_CTX_free(bn_ctx);

    // for (int i = 0; i <= t; i++)
    //     BN_free(coeff[i]);

    BN_free(order);
    BN_free(xi);

    EC_POINT_free(Xi);

    for (int i = 0; i < parties; i++)
        close(parties_sock[i]);

    delete[] parties_sock;
    delete[] parties_addr;
    delete[] parties_addr_size;
    delete[] key;
    delete[] iv;
}

void PARTIES::parse_option(int argc, char *argv[])
{
    const char *opt = "N:P:a:p:I:O:";
    char option;
    char *c;
    string str;

    while ((option = getopt(argc, argv, opt)) != -1)
    {
        switch (option)
        {
        case 'N':
            this->parties = atoi(optarg);
            parties_sock = new int[parties];
            parties_addr = new sockaddr_in[parties];
            parties_addr_size = new socklen_t[parties];
            break;

        case 'P':
            this->index = atoi(optarg);
            // printf("P option\n");
            // str = std::string(optarg);
            // std::cout << "P option - " << optarg <<std::endl;
            break;

        case 'a':
            str = string(optarg);

            c = strtok((char *)str.c_str(), ",");
            while (c)
            {
                this->str_addr.push_back(c);
                c = strtok(NULL, ",");
            }
            break;

        case 'p':
            this->port = atoi(optarg);
            break;

        case 'I':
            infile = string(optarg);
            lflag = true;
            break;

        case 'O':
            outfile = string(optarg);
            sflag = true;
            break;

        default:
            break;
        }
    }
}

void PARTIES::initSocket()
{
    if (str_addr.empty() || str_addr.size() < parties)
        handleErrors();

    for (int i = 0; i < parties; i++)
    {
        if (i < index - 1) // 접속
        {
            // 상황 봐서 wait 적용 필요.
            char *addr = new char[str_addr[i].length() + 1];
            copy(str_addr[i].begin(), str_addr[i].end(), addr);
            addr[str_addr[i].size()] = '\0';

            if ((parties_sock[i] = socket(PF_INET, SOCK_STREAM, 0)) == -1)
                handleErrors();

            memset(&parties_addr[i], 0, sizeof(parties_addr[i]));
            parties_addr[i].sin_family = AF_INET;
            parties_addr[i].sin_addr.s_addr = inet_addr(addr);
            parties_addr[i].sin_port = htons(port + i);

            if (connect(parties_sock[i], (struct sockaddr *)&parties_addr[i], sizeof(parties_addr[i])) == -1)
                handleErrors();

            delete[] addr;
        }
        else if (i == index - 1) // 서버 생성
        {

            if (index == parties)
                break;

            // char *addr = new char[str_addr[i].length() + 1];

            if ((parties_sock[i] = socket(PF_INET, SOCK_STREAM, 0)) == -1)
                handleErrors();

            parties_addr[i].sin_family = AF_INET;
            parties_addr[i].sin_addr.s_addr = htonl(INADDR_ANY);
            parties_addr[i].sin_port = htons(port + i);

            if (bind(parties_sock[i], (struct sockaddr *)&parties_addr[i], sizeof(parties_addr[i])) == -1)
                handleErrors();
            if (listen(parties_sock[i], parties) == -1)
                handleErrors();
        }
        else // 클라이언트 accept
        {
            parties_addr_size[i] = (socklen_t)sizeof(parties_addr[i]);
            if ((parties_sock[i] = accept(parties_sock[index - 1], (struct sockaddr *)&parties_addr[i], &parties_addr_size[i])) == -1)
                handleErrors();
        }
    }
}

void PARTIES::handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

void PARTIES::loadFile()
{
    ifstream ifs;
    ifs.open(infile);
    cout << "filename = " << infile << endl;

    ifs >> t >> n >> pi;
    printf("t = %d, n = %d, index = %d\n", t, n, pi);

    char *buf = new char[1024];
    memset(buf, 0x00, 1024);
    ifs >> buf;
    cout << "X = " << buf << endl;
    EC_POINT_hex2point(curve, buf, X, bn_ctx);
    printf("test1\n");

    memset(buf, 0x00, 1024);
    ifs >> buf;
    cout << "Xi = " << buf << endl;
    EC_POINT_hex2point(curve, buf, Xi, bn_ctx);

    memset(buf, 0x00, 1024);
    ifs >> buf;
    cout << "xi = " << buf << endl;
    BN_hex2bn(&xi, buf);

    coeff = new BIGNUM *[t + 1];
    for (int i = 0; i < t + 1; i++)
    {
        memset(buf, 0x00, 1024);

        coeff[i] = BN_new();
        ifs >> buf;
        BN_hex2bn(&coeff[i], buf);
        delete[] buf;
    }

    ifs.close();
}

void PARTIES::saveFile()
{
    fstream fs;
    fs.open(outfile);

    fs << t << n << pi << "\n";

    for (int i = 0; i < t + 1; i++) {
        char * buf = new char[256];

        memset(buf, 0x00, 256);
        strcpy(buf, BN_bn2hex(coeff[i]));

        fs << buf << "\n";
        delete[] buf;
    }

    // output xi
    // output t n
    // output Xi
    // output coefficients
    // output index
}

BIGNUM *PARTIES::L(int i, int x)
{
    BIGNUM *res = BN_new();
    BIGNUM *bnx = BN_new();
    BIGNUM *bni = BN_new();

    BN_dec2bn(&bnx, std::to_string(x).c_str());
    BN_dec2bn(&bni, std::to_string(i).c_str());
    BN_dec2bn(&res, std::to_string(1).c_str());

    for (int j = 2; j <= parties; j++)
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