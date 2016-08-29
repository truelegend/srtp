
#ifndef _SRTP_UNI_STREAM_H
#define _SRTP_UNI_STREAM_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "srtp.h"
#include "log.h"

#define MAX_KEY_LEN      92
#define MAX_PKG_LEN      1024
enum PKG_TYPE
{
    RTP = 0,
    SRTP = 1
};

class CSrtppkgTranslator
{
public:
    CSrtppkgTranslator(int enc, int auth, PKG_TYPE type, const char *base64key);
    virtual ~CSrtppkgTranslator();
    void EncodeRTP(int *len);
    void DecodeSRTP(int *len);
    void EncodeRTCP(int *len);
    void DecodeSRTCP(int *len);
    PKG_TYPE               m_pkg_type;
    unsigned char          m_pkg_buffer[MAX_PKG_LEN];
    int                    m_pkg_len;
    static void InitSrtpLib();
    static void DeInitSrtpLib();

private:
    char                   m_key[MAX_KEY_LEN];
    srtp_t                 m_session;
    srtp_policy_t          m_policy;
    int                    m_enc_type;
    int                    m_auth_type;
    //int                    m_cipher_key_len;

    void SetSRTPCryptoPolicy(srtp_crypto_policy_t *p);
    void GetkeyFromBase64String(const char *base64key);
};

#endif
