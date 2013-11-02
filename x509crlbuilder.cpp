#include "x509crlbuilder.h"

X509CrlBuilder::X509CrlBuilder(X509 *ca, EVP_PKEY *caKey)
    : ca(ca)
    , caKey(caKey)
{ }

X509_CRL *X509CrlBuilder::build()
{
    X509_CRL *crl = X509_CRL_new();
    X509_CRL_set_version(crl, 1);
    X509_CRL_set_issuer_name(crl, ca->cert_info->subject);
    ASN1_TIME_set(X509_CRL_get_lastUpdate(crl), time(NULL));
    crl->crl->nextUpdate = ASN1_TIME_new();
    ASN1_TIME_set(X509_CRL_get_nextUpdate(crl), time(NULL)+31*24*60*60);

    // Sign
    X509_CRL_sign(crl, caKey, EVP_sha1());

    return crl;
}
