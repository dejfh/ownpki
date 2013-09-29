#include "rsakeybuilder.h"

#include <openssl/rsa.h>

EVP_PKEY *RsaKeyBuilder::createRsaKey(int bits)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
    EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}
