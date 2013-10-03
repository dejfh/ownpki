#ifndef OWNPKI_H
#define OWNPKI_H

#include <vector>
#include <string>

class X509Builder;

class OwnPKI
{
    std::string rndFileName;

    std::string C, O, OU, CN, E;
    long serialNumber;
    long validity;

    std::string fileName;
    std::string keyFileName;
    std::vector<std::string> altDns;

    std::string caFileName;
    std::string caKeyFileName;
    std::string caCrtUrl;
    std::string caCrlUrl;

    std::string passwd;

    std::string usage;

    X509Builder *xb;

    static int passwdCallback(char *buf, int size, int, void *ownpki);

    void makeBuilder();
public:
    OwnPKI();
    ~OwnPKI();

    int exec(int argc, const char *args[]);

    int newRnd();
    int newKey();
    int rootCA();
    int signIntermediateCA();
    int sign();

    int crl();
};

#endif // OWNPKI_H
