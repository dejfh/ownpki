#ifndef X509BUILDER_H
#define X509BUILDER_H

#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOCRYPT
#endif

#include <iostream>
//#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "asnref.h"

class X509Builder
{
public:
    enum CertUsage
    {
        CRT_USAGE_CA            = 0x01,
        CRT_USAGE_SERVER        = 0x02,
        CRT_USAGE_CLIENT        = 0x04,
        CRT_USAGE_IPSECServer   = 0x08 | CRT_USAGE_SERVER
    };

    enum NameType
    {
        NAME_TYPE_DNS           = GEN_DNS,
        NAME_TYPE_IPADDRESS     = GEN_IPADD,
        NAME_TYPE_EMAIL         = GEN_EMAIL
    };

    X509Builder();
    ~X509Builder();

private:
    EVP_PKEY *key;

    RefNameEntry C;
    RefNameEntry O;
    RefNameEntry OU;
//    RefNameEntry DN;
    RefNameEntry CN;
    RefNameEntry E;

    CRL_DIST_POINTS *crlDistPoints;

    GENERAL_NAMES *subjectAltNames;

    RefAuthorityInfoAccess authInfoAccess;

    long valid_seconds;

public:
    X509 *build(X509 *ca, EVP_PKEY *caKey, long serialNumber, CertUsage usage);

    void setKey(EVP_PKEY *key);

    void setCountry(const char *c);
    void setOrganisation(const char *o);
    void setOrganisationUnit(const char *ou);
//    void setDistinguishedName(const char *dn);
    void setCommonName(const char *cn);
    void setEmailAddress(const char *e);

    void addAltName(const char *dns, NameType type);
    void addCrlDistPoint(const char *url);
    void addAuthorityInfoAccessCrt(const char *url);
    void addAuthorityInfoAccessOCSP(const char *url);

    void setValidity(const long seconds);

    X509 *buildRootCA();
    X509 *buildIntermediateCA(X509 *ca, EVP_PKEY *caKey, long serialNumber);
    X509 *buildCert(X509 *ca, EVP_PKEY *caKey, long serialNumber, CertUsage usage);
};

#endif // X509BUILDER_H
