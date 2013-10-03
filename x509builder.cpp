#include "x509builder.h"

#include "extensions.h"

X509Builder::X509Builder()
    : valid_seconds(20*365*24*60*60)
    , crlDistPoints(NULL)
    , subjectAltNames(NULL)
{
}

X509Builder::~X509Builder()
{
    if (crlDistPoints)
        sk_DIST_POINT_pop_free(crlDistPoints, DIST_POINT_free);
    if (subjectAltNames)
        sk_GENERAL_NAME_pop_free(subjectAltNames, GENERAL_NAME_free);
}

inline bool flagsSet(int val, int flags)
{
    return (val & flags) == flags;
}

X509 *X509Builder::build(X509 *ca, EVP_PKEY *caKey, long serialNumber, CertUsage usage)
{
    X509 *x = X509_new();

    // If no CA is given create self-signed
    if (!ca)
    {
        ca = x;
        caKey = key;
    }

    // Set X509 Version
    X509_set_version(x, 2);

    // Set Serial Number
    ASN1_INTEGER_set(X509_get_serialNumber(x), serialNumber);

    // Set Certified Public Key
    X509_set_pubkey(x, key);

    // Create KeyID (sha1 hash of Public Key)
    unsigned char keyHash[EVP_MAX_MD_SIZE];
    unsigned int keyHashLen;
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);

        ASN1_BIT_STRING *key = x->cert_info->key->public_key;
        EVP_DigestUpdate(ctx, key->data, key->length);
        EVP_DigestFinal(ctx, keyHash, &keyHashLen);
        EVP_MD_CTX_destroy(ctx);
    }

    // Set Validity Period
    ASN1_TIME_set(X509_get_notBefore(x), time(NULL));
    ASN1_TIME_set(X509_get_notAfter(x), time(NULL)+valid_seconds);

    // Set Key Identifier
    {
        RefOctString id(true);
        ASN1_OCTET_STRING_set(id, keyHash, keyHashLen);

        RefExtension ext(X509V3_EXT_i2d(NID_subject_key_identifier, 0, id));
        X509_add_ext(x, ext, -1);
    }

    // Set Authority Key Identifier
    {
        int abc = X509_get_ext_by_NID(ca, NID_subject_key_identifier, -1);
        X509_EXTENSION *caExt = X509_get_ext(ca, abc);

        RefAuthKeyId id(true);
        id->keyid = (ASN1_OCTET_STRING *)X509V3_EXT_d2i(caExt);

        RefExtension ext(X509V3_EXT_i2d(NID_authority_key_identifier, 0, id));
        X509_add_ext(x, ext, -1);
    }

    // Set Subject Name
    {
        RefName name(true);
        if (C.ptr)
            X509_NAME_add_entry(name, C, -1, 0);
        if (O.ptr)
            X509_NAME_add_entry(name, O, -1, 0);
        if (OU.ptr)
            X509_NAME_add_entry(name, OU, -1, 0);
//        if (DN.ptr)
//            X509_NAME_add_entry(name, DN, -1, 0);
        if (CN.ptr)
            X509_NAME_add_entry(name, CN, -1, 0);
        if (E.ptr)
            X509_NAME_add_entry(name, E, -1, 0);

        X509_set_subject_name(x, name);
    }

    // Set Issuer Name
    X509_set_issuer_name(x, X509_get_subject_name(ca));

    // Set Subject Alternative Name
    if (subjectAltNames)
    {
        RefExtension ext(X509V3_EXT_i2d(NID_subject_alt_name, 0, subjectAltNames));
        X509_add_ext(x, ext, -1);
    }

    // Set Basic Constraints
    {
        RefBasicConstraints bc(true);

        if (flagsSet(usage, CRT_USAGE_CA))
            bc->ca = 255;
        else
            bc->ca = 0;

        RefExtension ext(X509V3_EXT_i2d(NID_basic_constraints, 0, bc));
        X509_add_ext(x, ext, -1);
    }

    // Set Netscape Usage
    {
        RefBitString bs(true);
        if (flagsSet(usage, CRT_USAGE_CA)) {
            ASN1_BIT_STRING_set_bit(bs, NSCT_BIT_sslCA, 1);
            ASN1_BIT_STRING_set_bit(bs, NSCT_BIT_emailCA, 1);
            ASN1_BIT_STRING_set_bit(bs, NSCT_BIT_objCA, 1);
        }
        if (flagsSet(usage, CRT_USAGE_SERVER))
            ASN1_BIT_STRING_set_bit(bs, NSCT_BIT_server, 1);
        if (flagsSet(usage, CRT_USAGE_CLIENT))
            ASN1_BIT_STRING_set_bit(bs, NSCT_BIT_client, 1);

        RefExtension ext(X509V3_EXT_i2d(NID_netscape_cert_type, 0, bs));
        X509_add_ext(x, ext, -1);
    }

    // Set Key Usage
    {
        RefBitString bs(true);

        if (flagsSet(usage, CRT_USAGE_CA)) {
            ASN1_BIT_STRING_set_bit(bs, KU_BIT_keyCertSign, 1);
            ASN1_BIT_STRING_set_bit(bs, KU_BIT_cRLSign, 1);
        }
        if (flagsSet(usage, CRT_USAGE_SERVER)) {
            ASN1_BIT_STRING_set_bit(bs, KU_BIT_digitalSignature, 1);
            ASN1_BIT_STRING_set_bit(bs, KU_BIT_contentCommitment, 1);
            ASN1_BIT_STRING_set_bit(bs, KU_BIT_keyEncipherment, 1);
            ASN1_BIT_STRING_set_bit(bs, KU_BIT_dataEncipherment, 1);
            ASN1_BIT_STRING_set_bit(bs, KU_BIT_keyAgreement, 1);
        }

        RefExtension ext(X509V3_EXT_i2d(NID_key_usage, 0, bs));
        X509_add_ext(x, ext, -1);
    }

    // Set Extended Usage
    if (flagsSet(usage, CRT_USAGE_SERVER))
    {
        EXTENDED_KEY_USAGE *eku = EXTENDED_KEY_USAGE_new();

        sk_ASN1_OBJECT_push(eku, OBJ_txt2obj("1.3.6.1.5.5.7.3.1", 0)); // ServerAuthentication
        if (flagsSet(usage, CRT_USAGE_IPSECServer))
            sk_ASN1_OBJECT_push(eku, OBJ_txt2obj("1.3.6.1.5.5.8.2.2", 0)); // IPsecurityIKEintermediate

        RefExtension ext(X509V3_EXT_i2d(NID_ext_key_usage, 0, eku));
        X509_add_ext(x, ext, -1);

        sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
    }

    // Set CRL-Distribution Point
    if (crlDistPoints)
    {
        RefExtension ext(X509V3_EXT_i2d(NID_crl_distribution_points, 0, crlDistPoints));
        X509_add_ext(x, ext, -1);
    }

    // Set Authority Information Access
    if (authInfoAccess.ptr)
    {
        RefExtension ext(X509V3_EXT_i2d(NID_info_access, 0, authInfoAccess.ptr));
        X509_add_ext(x, ext, -1);
    }

    // Sign
    X509_sign(x, caKey, EVP_sha1());

    return x;
}

void X509Builder::setKey(EVP_PKEY *key)
{ this->key = key; }

void X509Builder::setCountry(const char *c)
{ C = X509_NAME_ENTRY_create_by_NID(NULL, NID_countryName, MBSTRING_UTF8, (unsigned char*)c, -1); }

void X509Builder::setOrganisation(const char *o)
{ O = X509_NAME_ENTRY_create_by_NID(NULL, NID_organizationName, MBSTRING_UTF8, (unsigned char*)o, -1); }

void X509Builder::setOrganisationUnit(const char *ou)
{ OU = X509_NAME_ENTRY_create_by_NID(NULL, NID_organizationalUnitName, MBSTRING_UTF8, (unsigned char*)ou, -1); }

//void X509Builder::setDistinguishedName(const char *dn)
//{ DN = X509_NAME_ENTRY_create_by_NID(NULL, NID_distinguishedName, MBSTRING_UTF8, (unsigned char*)dn, -1); }

void X509Builder::setCommonName(const char *cn)
{ CN = X509_NAME_ENTRY_create_by_NID(NULL, NID_commonName, MBSTRING_UTF8, (unsigned char*)cn, -1); }

void X509Builder::setEmailAddress(const char *e)
{ E = X509_NAME_ENTRY_create_by_NID(NULL, NID_pkcs9_emailAddress, MBSTRING_UTF8, (unsigned char*)e, -1); }

void X509Builder::addAltName(const char *name, NameType type)
{
    if (!subjectAltNames)
        subjectAltNames = GENERAL_NAMES_new();

    GENERAL_NAME *gn = a2i_GENERAL_NAME(NULL, NULL, NULL, type, (char *)name, 0);
    sk_GENERAL_NAME_push(subjectAltNames, gn);
}

void X509Builder::addCrlDistPoint(const char *url)
{
    if (!crlDistPoints)
        crlDistPoints = CRL_DIST_POINTS_new();

    DIST_POINT *crlDistPoint = DIST_POINT_new();
    crlDistPoint->distpoint = DIST_POINT_NAME_new();
    crlDistPoint->distpoint->type = 0;

    crlDistPoint->distpoint->name.fullname = GENERAL_NAMES_new();
    GENERAL_NAME *name = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_URI, (char *)url, 0);
    sk_GENERAL_NAME_push(crlDistPoint->distpoint->name.fullname, name);

    sk_DIST_POINT_push(crlDistPoints, crlDistPoint);
}

void X509Builder::addAuthorityInfoAccessCrt(const char *url)
{
    if (!authInfoAccess.ptr) authInfoAccess._new();

    ACCESS_DESCRIPTION *ad = ACCESS_DESCRIPTION_new();
    ad->method = OBJ_nid2obj(NID_ad_ca_issuers);
    ad->location = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_URI, (char *)url, 0);

    sk_ACCESS_DESCRIPTION_push(authInfoAccess.ptr, ad);
}

void X509Builder::addAuthorityInfoAccessOCSP(const char *url)
{
    if (!authInfoAccess.ptr) authInfoAccess._new();

    ACCESS_DESCRIPTION *ad = ACCESS_DESCRIPTION_new();
    ad->method = OBJ_nid2obj(NID_ad_OCSP);
    ad->location = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_URI, (char *)url, 0);

    sk_ACCESS_DESCRIPTION_push(authInfoAccess.ptr, ad);
}

void X509Builder::setValidity(const long seconds)
{ valid_seconds = seconds; }

X509 *X509Builder::buildRootCA()
{
    return build(NULL, NULL, 1, CRT_USAGE_CA);
}

X509 *X509Builder::buildIntermediateCA(X509 *ca, EVP_PKEY *caKey, long serialNumber)
{
    return build(ca, caKey, serialNumber, CRT_USAGE_CA);
}

X509 *X509Builder::buildCert(X509 *ca, EVP_PKEY *caKey, long serialNumber, X509Builder::CertUsage usage)
{
    return build(ca, caKey, serialNumber, usage);
}
