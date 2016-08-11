#ifndef _SRTP_BID_STREAM1_H
#define _SRTP_BID_STREAM1_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "srtppkgtranslator.h"
#include "rtpqueue.h"
#include "log.h"
//#include "send_srtp.h"
class CSrtpBidirectStream
{
public:
    CSrtpBidirectStream(char* local_addr,unsigned int local_port,
                        char* peer_addr,unsigned int peer_port, int ip_type);
    ~CSrtpBidirectStream();
    bool BindLocalPortforRTP();
    bool BindLocalPortforRTCP();
    void SendSRTP(int len);
    int ReceiveSRTP();
    void SendSRTCP(int len);
    int ReceiveSRTCP();

    CSrtppkgTranslator    *m_pSrtpTranslator;
    CSrtppkgTranslator    *m_pRtpTranslator;
    CRtpQueue              m_rtpque;

private:

    struct sockaddr_in     m_localaddr;
    struct sockaddr_in     m_peeraddr;
    int                    m_rtp_sockfd; //= socket(AF_INET,SOCK_DGRAM,0);

    struct sockaddr_in     m_localaddr_rtcp;
    struct sockaddr_in     m_peeraddr_rtcp;
    int                    m_rtcp_sockfd;
    static const int       TIMEOUT = 5;

    struct sockaddr_in6    m_localaddr_v6;
    struct sockaddr_in6    m_peeraddr_v6;
    struct sockaddr_in6    m_localaddr_rtcp_v6;
    struct sockaddr_in6    m_peeraddr_rtcp_v6;

    int                    m_iptype;

};

#endif
