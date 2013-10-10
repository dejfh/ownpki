#define _SCL_SECURE_NO_WARNINGS

#include "ownpki.h"

#include <string.h>
#include <stdio.h>
#include <iostream>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "x509builder.h"
#include "x509crlbuilder.h"
#include "rsakeybuilder.h"

int main(int argc, const char *args[])
{
    OwnPKI ownpki;
    return ownpki.exec(argc, args);
}

using namespace std;

OwnPKI::OwnPKI()
    : serialNumber(0)
    , validity(0)
    , xb(NULL)
{ }

OwnPKI::~OwnPKI()
{
    if (xb)
        delete xb;
}

void SetStdinEcho(bool enable = true);

inline void beginOp(const char *op)
{ cout << op << " -"; }
inline void continueOp(const char *op)
{ cout << " " << op << " -"; }
inline void finishOp()
{ cout << " done." << endl; }
inline void failOp()
{ cout << " failed." << endl; }

int OwnPKI::exec(int argc, const char *args[])
{

    // first argument is executable name
    argc--;
    args++;


    const char *cmd = (argc-- > 0) ? *args++ : NULL;

    bool passin = false;

    while (argc > 0)
    {
        if (strcmp(*args, "-rnd") == 0)
            if (--argc <= 0) goto noargval;
            else rndFileName = *++args;

        else if (strcmp(*args, "-C") == 0)
            if (--argc <= 0) goto noargval;
            else C = *++args;
        else if (strcmp(*args, "-O") == 0)
            if (--argc <= 0) goto noargval;
            else O = *++args;
        else if (strcmp(*args, "-OU") == 0)
            if (--argc <= 0) goto noargval;
            else OU = *++args;
        else if (strcmp(*args, "-CN") == 0)
            if (--argc <= 0) goto noargval;
            else CN = *++args;
        else if (strcmp(*args, "-E") == 0)
            if (--argc <= 0) goto noargval;
            else E = *++args;
        else if (strcmp(*args, "-days") == 0)
            if (--argc <= 0) goto noargval;
            else validity = int(atof(*++args) * 24 * 60 * 60);

        else if (strcmp(*args, "-out") == 0)
            if (--argc <= 0) goto noargval;
            else fileName = *++args;
        else if (strcmp(*args, "-key") == 0)
            if (--argc <= 0) goto noargval;
            else keyFileName = *++args;
        else if (strcmp(*args, "-altdns") == 0)
            if (--argc <= 0) goto noargval;
            else altDns.push_back(*++args);

        else if (strcmp(*args, "-ca") == 0)
            if (--argc <= 0) goto noargval;
            else caFileName = *++args;
        else if (strcmp(*args, "-caKey") == 0)
            if (--argc <= 0) goto noargval;
            else caKeyFileName = *++args;
        else if (strcmp(*args, "-caCrtUrl") == 0)
            if (--argc <= 0) goto noargval;
            else caCrtUrl = *++args;
        else if (strcmp(*args, "-caCrlUrl") == 0)
            if (--argc <= 0) goto noargval;
            else caCrlUrl = *++args;

        else if (strcmp(*args, "-pass") == 0)
            if (--argc <= 0) goto noargval;
            else passwd = *++args;
        else if (strcmp(*args, "-passin") == 0)
            passin = true;

        else if (strcmp(*args, "-usage") == 0)
            if (--argc <= 0) goto noargval;
            else usage = *++args;

        else if (strcmp(*args, "-serial") == 0)
            if (--argc <= 0) goto noargval;
            else serialNumber = int(atol(*++args));

        else
            goto badarg;

        argc--;
        args++;
    }

    if (!cmd) {
        cout << "Available Commands" << endl <<
                "newRnd, newKey, rootCA, signCA, sign, crl" << endl << endl <<
                "Available Arguments" << endl <<
                "-rnd, -C, -O, -OU, -CN, -E, -days, -out, -key, -altdns, -ca, -caKey, -caCrtUrl, -caCrlUrl, -pass, -passin, -usage, -serial" << endl;
        return 0;
    }

    if (passin)
    {
        char buffer[1024];
        SetStdinEcho(false);
        cout << "keyfile password: ";
        cin.getline(buffer, sizeof(buffer));
        SetStdinEcho(true);
        passwd = buffer;
        if (passwd.length())
            cout << "* * *" << endl;
        else
            cout << "no password" << endl;
    }

    beginOp("Loading OpenSSL Algorithms");
    OpenSSL_add_all_algorithms();
    finishOp();

    beginOp("Init Random");
#ifdef WIN32
    continueOp("loading screen");
    RAND_screen();
#endif
    if (rndFileName.length()) {
        continueOp("loading file");
        if (!RAND_load_file(rndFileName.c_str(), -1))
            goto badrand;
    }
    if (RAND_status() == 0) {
        goto badrand;
    }
    else
        finishOp();

    int r;
    if (strcmp(cmd, "newRnd") == 0)
        r = newRnd();
    else if (strcmp(cmd, "newKey") == 0)
        r = newKey();
    else if (strcmp(cmd, "rootCA") == 0)
        r = rootCA();
    else if (strcmp(cmd, "signCA") == 0)
        r = signIntermediateCA();
    else if (strcmp(cmd, "sign") == 0)
        r = sign();
    else if (strcmp(cmd, "crl") == 0)
        r = crl();
    else
        goto badcmd;

    if (r == 0 && rndFileName.length()) {
        beginOp("Writing random file");
        if (!RAND_write_file(rndFileName.c_str())) {
            failOp();
            r = 5;
        }
        else
            finishOp();
    }

    return r;

badcmd:
    cout << "Unknown Command: " << cmd << endl;
    return 1;

badarg:
    cout << "Unknown Argument: " << *args << endl;
    return 2;

noargval:
    cout << "Argument needs Value: " << *args << endl;
    return 3;

badrand:
    failOp();
    return 4;
}

int OwnPKI::passwdCallback(char *buf, int size, int, void *ownpki)
{
    const char *passwd = ((OwnPKI *)ownpki)->passwd.c_str();
    int length = min(size-1, (int)strlen(passwd));
    memcpy(buf, passwd, length);
    buf[length] = 0;
    return (int)strlen(buf);
}

void OwnPKI::makeBuilder()
{
    if (xb)
        delete xb;
    xb = new X509Builder();

    if (C.length()) xb->setCountry(C.c_str());
    if (O.length()) xb->setOrganisation(O.c_str());
    if (OU.length()) xb->setOrganisationUnit(OU.c_str());
    if (CN.length()) xb->setCommonName(CN.c_str());
    if (E.length()) xb->setEmailAddress(E.c_str());
    if (caCrlUrl.length()) xb->addCrlDistPoint(caCrlUrl.c_str());
    for (std::vector<std::string>::const_iterator it=altDns.begin(); it != altDns.end(); ++it)
        xb->addAltName((*it).c_str(), X509Builder::NAME_TYPE_DNS);
    if (caCrtUrl.length()) xb->addAuthorityInfoAccessCrt(caCrtUrl.c_str());
    xb->setValidity(validity);
}

int OwnPKI::newRnd()
{
    beginOp("Writing new random file");
    if (!RAND_write_file(fileName.c_str()))
    { failOp(); return 100; }
    finishOp();
    return 0;
}

int OwnPKI::newKey()
{
    beginOp("Generating Key");
    RefPKey key(RsaKeyBuilder::createRsaKey(4096));
    finishOp();

    beginOp("Writing Private Keyfile");
    BIO *bio = BIO_new_file(keyFileName.c_str(), "w");
    int r;
    if (strlen(passwd.c_str())>0)
        r = PEM_write_bio_PrivateKey(bio, key, EVP_aes_256_cbc(), NULL, 0, &passwdCallback, this);
    else
        r = PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    BIO_flush(bio);
    BIO_free(bio);
    if (!r) {
        failOp();
        return 100;
    }
    finishOp();

    beginOp("Writing Public Keyfile");
    bio = BIO_new_file(fileName.c_str(), "w");
    r = PEM_write_bio_PUBKEY(bio, key);
    BIO_flush(bio);
    BIO_free(bio);
    if (!r) {
        failOp();
        return 100;
    }
    finishOp();
    return 0;
}

int OwnPKI::rootCA()
{
    if (validity <= 0) validity = 30 * 365 * 24 * 60 * 60;
    if (serialNumber <= 0) serialNumber = 1;

    BIO *bio;

    beginOp("Reading Private Key");
    bio = BIO_new_file(caKeyFileName.c_str(), "r");
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, &passwdCallback, this);
    BIO_free(bio);
    if (!key) { failOp(); return 100; }
    finishOp();

    beginOp("Building certificate");
    makeBuilder();
    xb->setKey(key);
    RefX509 x(xb->buildRootCA());
    if (!x.ptr) { failOp(); return 100; }
    finishOp();

    beginOp("Writing certificate");
    bio = BIO_new_file(caFileName.c_str(), "w");
    int r = PEM_write_bio_X509(bio, x);
    BIO_flush(bio);
    BIO_free(bio);
    EVP_PKEY_free(key);

    if (!r) {
        failOp();
        return 100;
    }
    finishOp();
    return 0;
}

int OwnPKI::signIntermediateCA()
{
    usage = "ca";
    return sign();
}

int OwnPKI::sign()
{
    X509Builder::CertUsage usage;
    if (this->usage.compare("ca") == 0)
        usage = X509Builder::CRT_USAGE_CA;
    else if (this->usage.compare("server") == 0)
        usage = X509Builder::CRT_USAGE_SERVER;
    else if (this->usage.compare("ipsec") == 0)
        usage = X509Builder::CRT_USAGE_IPSECServer;
    else
        usage = X509Builder::CRT_USAGE_CLIENT;

    if (validity <= 0)
        validity = (usage == X509Builder::CRT_USAGE_CA ? 3650 : 548) *24*60*60;

    BIO *bio;

    beginOp("Reading Public Key");
    bio = BIO_new_file(keyFileName.c_str(), "r");
    RefPKey key(PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL));
    BIO_free(bio);
    if (!key) { failOp(); return 100; }
    finishOp();

    beginOp("Reading CA Private Key");
    bio = BIO_new_file(caKeyFileName.c_str(), "r");
    RefPKey cakey(PEM_read_bio_PrivateKey(bio, NULL, &passwdCallback, this));
    BIO_free(bio);
    if (!cakey) { failOp(); return 100; }
    finishOp();

    beginOp("Reading CA Certificate");
    bio = BIO_new_file(caFileName.c_str(), "r");
    RefX509 ca(PEM_read_bio_X509(bio, NULL, NULL, NULL));
    BIO_free(bio);
    if (!ca) { failOp(); return 100; }
    finishOp();

    beginOp("Building Certificate");
    makeBuilder();
    xb->setKey(key);
    RefX509 x(xb->buildCert(ca, cakey, serialNumber, usage));
    if (!x) { failOp(); return 100; }
    finishOp();

    beginOp("Writing Certificate");
    bio = BIO_new_file(fileName.c_str(), "w");
    int r = PEM_write_bio_X509(bio, x);
    BIO_flush(bio);
    BIO_free(bio);
    if (!r) { failOp(); return 100; }
    finishOp();

    return 0;
}

int OwnPKI::crl()
{
    BIO *bio;
    beginOp("Reading CA Private Key");
    bio = BIO_new_file(caKeyFileName.c_str(), "r");
    RefPKey cakey(PEM_read_bio_PrivateKey(bio, NULL, &passwdCallback, this));
    BIO_free(bio);
    if (!cakey) { failOp(); return 100; }
    finishOp();

    beginOp("Reading CA Certificate");
    bio = BIO_new_file(caFileName.c_str(), "r");
    RefX509 ca(PEM_read_bio_X509(bio, NULL, NULL, NULL));
    BIO_free(bio);
    if (!ca) { failOp(); return 100; }
    finishOp();

    beginOp("Building Certificate Revocation List");
    X509CrlBuilder builder(ca, cakey);
    RefX509Crl crl(builder.build());
    finishOp();

    beginOp("Writing Certificate Revocation List");
    bio = BIO_new_file(fileName.c_str(), "w");
    int r = PEM_write_bio_X509_CRL(bio, crl);
    BIO_flush(bio);
    BIO_free(bio);
    if (!r) { failOp(); return 100; }
    finishOp();

    return 0;
}
