#include "srtppkgtranslator.h"

CSrtppkgTranslator::CSrtppkgTranslator(int enc, int auth, PKG_TYPE type, const char *base64key)
{
    m_enc_type = enc;
    m_auth_type = auth;
    m_pkg_type = type;
    memset(&m_policy, 0x0, sizeof(srtp_policy_t));
    m_session = NULL;
    srtp_err_status_t status;
    /*status = srtp_init();
    if (status)
    {
        printf("error: srtp initialization failed with error code %d\n", status);
        exit(1);
    }*/

    SetSRTPCryptoPolicy(&m_policy.rtp);
    SetSRTPCryptoPolicy(&m_policy.rtcp);
    GetkeyFromBase64String(base64key);

    m_policy.key                 = (uint8_t *)m_key;
    m_policy.ssrc.type           = (type == RTP)?ssrc_any_outbound:ssrc_any_inbound;//
    //printf("ssrc.type is %d\n", m_policy.ssrc.type );
    //policy.ssrc.value          = ssrc;
    m_policy.ekt                 = NULL;
    m_policy.next                = NULL;
    m_policy.window_size         = 128;
    m_policy.allow_repeat_tx     = 0;
    m_policy.rtp.sec_serv        = sec_serv_conf_and_auth;
    m_policy.rtcp.sec_serv        = sec_serv_conf_and_auth;

    status = srtp_create(&m_session, &m_policy);
    if (status)
    {
        //fprintf(stderr,"error: srtp_create() failed with code %d\n",status);
        LOG(ERROR,"srtp_create() failed with code %d\n",status);
        exit(1);
    }
    LOG(DEBUG,"srtp_create succeed");
}
CSrtppkgTranslator::~CSrtppkgTranslator()
{
    //srtp_err_status_t status;

}
void CSrtppkgTranslator::GetkeyFromBase64String(const char *base64key)
{
    LOG(DEBUG,"the base64 encoded key is %s", base64key);
    FILE *pipe_fp;
    char cmd[1024];

    sprintf(cmd, "echo -n '%s' | base64 -d", base64key);
    LOG(DEBUG,"the shell cmd is: %s", cmd);
    pipe_fp = popen(cmd,"r");
    if (pipe_fp == NULL)
    {
        LOG(ERROR,"failed to open pipe file");
        exit(1);
    }
    fread(m_key,sizeof(char),m_policy.rtp.cipher_key_len,pipe_fp);
    for(int i=0; i<m_policy.rtp.cipher_key_len; i++)
    {
        // As needed
        //printf("%02x",m_key[i]);
    }
    pclose(pipe_fp);
}
void CSrtppkgTranslator::SetSRTPCryptoPolicy(srtp_crypto_policy_t *p)
{
    if (m_enc_type==128 && m_auth_type==80)
    {
        LOG(DEBUG,"set crypto policy via srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80");
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(p);
    }
    if (m_enc_type==128 && m_auth_type==32)
    {
        LOG(DEBUG,"set crypto policy via srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32");
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(p);
    }
    if (m_enc_type==256 && m_auth_type ==80)
    {
        LOG(DEBUG,"set crypto policy via srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80");
        srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(p);
    }
    if (m_enc_type==256 && m_auth_type==32)
    {
        LOG(DEBUG,"set crypto policy via srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32");
        srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(p);
    }
}
void CSrtppkgTranslator::EncodeRTP(int *len)
{
    if (!m_session)
    {
        //printf("m_session is NULL, exit\n");
        LOG(ERROR,"m_session is NULL!");
        exit(1);
    }
    int status = srtp_protect(m_session, m_pkg_buffer, len);
    if(status)
    {
        //fprintf(stderr, "error: srtp protection failed with code %d\n", status);
        LOG(ERROR,"srtp protection failed with error code %d", status);
        exit(1);
    }
}
void CSrtppkgTranslator::DecodeSRTP(int *len)
{
    int status = srtp_unprotect(m_session, m_pkg_buffer, len);
    if (status)
    {
        //fprintf(stderr, "error: srtp unprotection failed with code %d\n", status);
        LOG(ERROR,"srtp unprotection failed with error code %d", status);
        exit(1);
    }
}
void CSrtppkgTranslator::EncodeRTCP(int *len)
{
    if (!m_session)
    {
        LOG(ERROR,"m_session is NULL!");
        exit(1);
    }
    //printf("EncodeRTP before protection: %d\n", *len);
    int status = srtp_protect_rtcp(m_session, m_pkg_buffer, len);
    //printf("EncodeRTP after protection: %d\n", *len);
    if(status)
    {
        //fprintf(stderr, "error: srtp protection failed with code %d\n", status);
        LOG(ERROR,"rtcp protection failed with error code %d", status);
        exit(1);
    }
}
void CSrtppkgTranslator::DecodeSRTCP(int *len)
{
    int status = srtp_unprotect_rtcp(m_session, m_pkg_buffer, len);
    if (status)
    {
        //fprintf(stderr, "error: srtp unprotection failed with code %d\n", status);
        LOG(ERROR,"srtcp unprotection failed with error code %d", status);
        exit(1);
    }
}
void CSrtppkgTranslator::InitSrtpLib()
{
    LOG(DEBUG,"init srtplib");
    srtp_err_status_t status = srtp_init();
    if (status)
    {
        //printf("error: srtp initialization failed with error code %d\n", status);
        LOG(ERROR,"srtp initialization failed with error code %d", status);
        exit(1);
    }
}
void CSrtppkgTranslator::DeInitSrtpLib()
{
    LOG(DEBUG,"shutdown srtplib");
    srtp_err_status_t status = srtp_shutdown();
    if (status)
    {
        //printf("error: srtp shutdown failed with error code %d\n", status);
        LOG(ERROR,"srtp deinitialization failed with error code %d", status);
        exit(1);
    }
}
