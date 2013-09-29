#ifndef ASNREF_H
#define ASNREF_H

//class AsnRefASN1_BIT_STRING {
//public:
//    AsnRefASN1_BIT_STRING() : ptr(NULL) { }
//    AsnRefASN1_BIT_STRING(ASN1_BIT_STRING *ptr) : ptr(ptr) { }
//    ~AsnRefASN1_BIT_STRING() { ASN1_BIT_STRING_free(ptr); }
//    ASN1_BIT_STRING *ptr;
//};


#define DEF_ASN_REF(T,N) \
class N { \
public: \
    inline N(bool create = false) : ptr(create ? T##_new() : NULL) { } \
    inline N(T *ptr) : ptr(ptr) { } \
    inline ~N() { T##_free(ptr); } \
    T *ptr; \
    inline void _new() { T##_free(ptr); ptr = T##_new(); } \
    inline T *take() { T *t_ptr(ptr); ptr = NULL; return t_ptr; } \
    inline T *operator =(T* n_ptr) { T##_free(ptr); ptr = n_ptr; return ptr; } \
    inline T &operator *() { return *ptr; } \
    inline T *operator ->() { return ptr; } \
    inline operator T*() { return ptr; } \
    inline operator bool() { return ptr != NULL; } \
};

DEF_ASN_REF(BASIC_CONSTRAINTS, RefBasicConstraints)
DEF_ASN_REF(ASN1_BIT_STRING, RefBitString)
DEF_ASN_REF(ASN1_IA5STRING, RefIA5String)
DEF_ASN_REF(X509, RefX509)
DEF_ASN_REF(X509_NAME, RefName)
DEF_ASN_REF(X509_NAME_ENTRY, RefNameEntry)
DEF_ASN_REF(EVP_PKEY, RefPKey)
DEF_ASN_REF(X509_EXTENSION, RefExtension)
DEF_ASN_REF(AUTHORITY_KEYID, RefAuthKeyId)
DEF_ASN_REF(ASN1_OCTET_STRING, RefOctString)
DEF_ASN_REF(DIST_POINT, RefDistPoint)
DEF_ASN_REF(AUTHORITY_INFO_ACCESS, RefAuthorityInfoAccess)

#endif // ASNREF_H
