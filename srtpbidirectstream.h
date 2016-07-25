#ifndef _SRTP_BID_STREAM1_H
#define _SRTP_BID_STREAM1_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "srtppkgtranslator.h"
#include "log.h"
//#include "send_srtp.h"
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

    private:
        
        struct sockaddr_in     m_localaddr;
        struct sockaddr_in     m_peeraddr;
        int                    m_rtp_sockfd; //= socket(AF_INET,SOCK_DGRAM,0);

        struct sockaddr_in     m_localaddr_rtcp;
        struct sockaddr_in     m_peeraddr_rtcp;
        int                    m_rtcp_sockfd;

};

#endif
