#include "rsakeybuilder.h"

#include <openssl/rsa.h>

EVP_PKEY *RsaKeyBuilder::createRsaKey(int bits)
{
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    if (!RSA_generate_key_ex(rsa, 4096, bn, NULL))
    { RSA_free(rsa); rsa = NULL; }
    BN_free(bn);
    if (!rsa)
        return NULL;
    EVP_PKEY *key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key, rsa);
    return key;
}
