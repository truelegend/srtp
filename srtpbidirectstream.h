#ifndef _SRTP_BID_STREAM1_H
#define _SRTP_BID_STREAM1_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "srtppkgtranslator.h"
#include "rtpqueue.h"
#include "log.h"
//#include "send_srtp.h"

#define SOCK_ADDR_SIZE(a) \
  (((a)->ss_family == AF_INET) ? sizeof(struct sockaddr_in) \
                               : sizeof(struct sockaddr_in6))

class CSrtpBidirectStream
{
public:
    CSrtpBidirectStream(char* local_addr,unsigned int local_port,
                        char* peer_addr,unsigned int peer_port);
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

    int                    m_rtp_sockfd; //= socket(AF_INET,SOCK_DGRAM,0);
    int                    m_rtcp_sockfd;
    static const int       TIMEOUT = 5;

    struct sockaddr_storage m_new_local_rtpaddr;
    struct sockaddr_storage m_new_peer_rtpaddr;
    struct sockaddr_storage m_new_local_rtcpaddr;
    struct sockaddr_storage m_new_peer_rtcpaddr;
};

#endif
