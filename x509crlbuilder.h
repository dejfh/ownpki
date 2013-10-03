#ifndef X509CRLBUILDER_H
#define X509CRLBUILDER_H

#include <openssl/evp.h>
#include <openssl/x509.h>

class X509CrlBuilder
{
    X509 *ca;
    EVP_PKEY *caKey;
public:
    X509CrlBuilder(X509 *ca, EVP_PKEY *caKey);

    X509_CRL *build();
};

#endif // X509CRLBUILDER_H
