#ifndef _SEND_SRTP_ARGUMENTS_H
#define _SEND_SRTP_ARGUMENTS_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include "log.h"


class CArgumentsHandler
{
public:
    const char              *m_pcap_file;
    char                    *m_local_addr;
    unsigned int             m_local_port;
    char                    *m_peer_addr;
    unsigned int             m_peer_port;
    const char              *m_local_base64_key;
    const char              *m_peer_base64_key;
    int                      m_cipher_key_len;
    int                      m_enc_type;
    int                      m_auth_type;
    int                      m_iptype;
    CArgumentsHandler(int argc, char **argv);
    bool VerifyArguments();
    void Usage();

private:

    int m_argc;
    char ** m_argv;
    bool IsBase64keyCorrect(const char *base64_key);
};


u_short GetRtpSeq(const u_char *pRTP);
#endif
