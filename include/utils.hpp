#include <iostream>
#include <string>
#include <cstring>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

using namespace std;
void handleErrors();
void polinomial_generator(int t, int n, int lambda, unsigned char **_x, unsigned char **_X);