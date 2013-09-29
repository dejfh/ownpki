#ifndef RSAKEYBUILDER_H
#define RSAKEYBUILDER_H

#include <openssl/evp.h>

class RsaKeyBuilder
{
public:
    static EVP_PKEY *createRsaKey(int bits = 4096);
};

#endif // RSAKEYBUILDER_H
