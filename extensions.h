#ifndef EXTENSIONS_H
#define EXTENSIONS_H

enum KeyUsageBits
{
    KU_BIT_digitalSignature     = 0,
    KU_BIT_nonRepudiation       = 1,                        // recent editions of X.509 have
    KU_BIT_contentCommitment    = KU_BIT_nonRepudiation,    // renamed this bit to contentCommitment
    KU_BIT_keyEncipherment      = 2,
    KU_BIT_dataEncipherment     = 3,
    KU_BIT_keyAgreement         = 4,
    KU_BIT_keyCertSign          = 5,
    KU_BIT_cRLSign              = 6,
    KU_BIT_encipherOnly         = 7,
    KU_BIT_decipherOnly         = 8
};

enum NetscapeCertTypeBits
{
    NSCT_BIT_client     = 0,
    NSCT_BIT_server     = 1,
    NSCT_BIT_email      = 2,
    NSCT_BIT_objsign    = 3,
    NSCT_BIT_reserved   = 4,
    NSCT_BIT_sslCA      = 5,
    NSCT_BIT_emailCA    = 6,
    NSCT_BIT_objCA      = 7
};

#endif // EXTENSIONS_H
