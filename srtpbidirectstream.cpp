#include "srtpbidirectstream.h"

CSrtpBidirectStream::CSrtpBidirectStream(char *local_addr,unsigned int local_port,
        char *peer_addr,unsigned int peer_port, int iptype)
{
    m_iptype = iptype;
    if (iptype == 4)
    {
        bzero(&m_localaddr, sizeof(m_localaddr));
        m_localaddr.sin_family = AF_INET;
        m_localaddr.sin_port = htons(local_port);
        m_localaddr.sin_addr.s_addr = inet_addr(local_addr);

        bzero(&m_peeraddr, sizeof(m_peeraddr));
        m_peeraddr.sin_family = AF_INET;
        m_peeraddr.sin_port = htons(peer_port);
        m_peeraddr.sin_addr.s_addr = inet_addr(peer_addr);

        bzero(&m_localaddr_rtcp, sizeof(m_localaddr_rtcp));
        m_localaddr_rtcp.sin_family = AF_INET;
        m_localaddr_rtcp.sin_port = htons(local_port+1);
        m_localaddr_rtcp.sin_addr.s_addr = inet_addr(local_addr);

        bzero(&m_peeraddr_rtcp, sizeof(m_peeraddr_rtcp));
        m_peeraddr_rtcp.sin_family = AF_INET;
        m_peeraddr_rtcp.sin_port = htons(peer_port+1);
        m_peeraddr_rtcp.sin_addr.s_addr = inet_addr(peer_addr);

        m_rtp_sockfd = socket(AF_INET,SOCK_DGRAM,0);
        LOG(DEBUG,"set the receiving rtp sockfd TIMEOUT timer");
        timeval tv;
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;
        if(setsockopt(m_rtp_sockfd,SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) != 0)
        {
            LOG(ERROR,"failed to set TIMEOUT for receiving socket");
            exit(1);
        }
        m_rtcp_sockfd = socket(AF_INET,SOCK_DGRAM,0);
    }
    else
    {
        LOG(DEBUG, "IPv6 address type");
        bzero(&m_localaddr_v6, sizeof(m_localaddr_v6));
        m_localaddr_v6.sin6_family = AF_INET6;
        m_localaddr_v6.sin6_port = htons(local_port);
        //m_localaddr_v6.sin_addr.s_addr = inet_addr(local_addr);
        inet_pton(AF_INET6, local_addr, &m_localaddr_v6.sin6_addr);

        bzero(&m_peeraddr_v6, sizeof(m_peeraddr_v6));
        m_peeraddr_v6.sin6_family = AF_INET6;
        m_peeraddr_v6.sin6_port = htons(peer_port);
        //m_peeraddr_v6.sin_addr.s_addr = inet_addr(peer_addr);
        inet_pton(AF_INET6, peer_addr, &m_peeraddr_v6.sin6_addr);

        bzero(&m_localaddr_rtcp_v6, sizeof(m_localaddr_rtcp_v6));
        m_localaddr_rtcp_v6.sin6_family = AF_INET6;
        m_localaddr_rtcp_v6.sin6_port = htons(local_port+1);
        //m_localaddr_rtcp_v6.sin_addr.s_addr = inet_addr(local_addr);
        inet_pton(AF_INET6, local_addr, &m_localaddr_rtcp_v6.sin6_addr);

        bzero(&m_peeraddr_rtcp_v6, sizeof(m_peeraddr_rtcp_v6));
        m_peeraddr_rtcp_v6.sin6_family = AF_INET6;
        m_peeraddr_rtcp_v6.sin6_port = htons(peer_port+1);
        //m_peeraddr_rtcp_v6.sin_addr.s_addr = inet_addr(peer_addr);
        inet_pton(AF_INET6, peer_addr, &m_peeraddr_rtcp_v6.sin6_addr);

        m_rtp_sockfd = socket(AF_INET6,SOCK_DGRAM,0);
        LOG(DEBUG,"set the receiving rtp sockfd TIMEOUT timer");
        timeval tv;
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;
        if(setsockopt(m_rtp_sockfd,SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) != 0)
        {
            LOG(ERROR,"failed to set TIMEOUT for receiving socket");
            exit(1);
        }
        m_rtcp_sockfd = socket(AF_INET6,SOCK_DGRAM,0);
    }

    
}
CSrtpBidirectStream::~CSrtpBidirectStream()
{
    //LOG(DEBUG,"close rtp/rtcp socket in ~CSrtpBidirectStream");
    close(m_rtp_sockfd);
    close(m_rtcp_sockfd);
}
bool CSrtpBidirectStream::BindLocalPortforRTP()
{
    if (m_iptype == 4)
    {
        if(bind(m_rtp_sockfd,(struct sockaddr *)&m_localaddr,sizeof(struct sockaddr)) == -1)
        {
            close(m_rtp_sockfd);
            LOG(ERROR,"error when trying to bind local ip/port for rtp");
            return false;
        }
    }
    else
    {
        if(bind(m_rtp_sockfd,(struct sockaddr *)&m_localaddr_v6,sizeof(struct sockaddr_in6)) == -1)
        {
            close(m_rtp_sockfd);
            LOG(ERROR,"error when trying to bind local ip/port for rtp");
            return false;
        }
    }
    
    return true;
}

bool CSrtpBidirectStream::BindLocalPortforRTCP()
{
    if (m_iptype == 4)
    {
        if(bind(m_rtcp_sockfd,(struct sockaddr *)&m_localaddr_rtcp,sizeof(struct sockaddr)) == -1)
        {
            close(m_rtcp_sockfd);
            printf("error when trying to bind local ip/port for rtcp");
            return false;
        }
    }
    else
    {
        if(bind(m_rtcp_sockfd,(struct sockaddr *)&m_localaddr_rtcp_v6,sizeof(struct sockaddr_in6)) == -1)
        {
            close(m_rtcp_sockfd);
            printf("error when trying to bind local ip/port for rtcp");
            return false;
        }
    }
    
    return true;
}

void CSrtpBidirectStream::SendSRTP(int rtp_len)
{
    if (!m_pRtpTranslator)
    {
        LOG(ERROR,"the pRTP pointer is NULL, exit");
        exit(1);
    }
    int n;
    if (m_iptype == 4)
    {
        n = sendto(m_rtp_sockfd,m_pRtpTranslator->m_pkg_buffer,rtp_len,
                   0,(struct sockaddr *)&m_peeraddr, sizeof(m_peeraddr));
    }
    else
    {
        n = sendto(m_rtp_sockfd,m_pRtpTranslator->m_pkg_buffer,rtp_len,
                   0,(struct sockaddr *)&m_peeraddr_v6, sizeof(m_peeraddr_v6));
    }
    
    if (n < 0)
    {
        LOG(ERROR,"sending data failed, error code: %d, error info: %s",errno,strerror(errno));
        exit(1);
    }
    LOG(DEBUG,"%d srtp bytes data has been sent out successfully", n);
}
int CSrtpBidirectStream::ReceiveSRTP()
{
    if (!m_pSrtpTranslator)
    {
        LOG(ERROR,"the pRTP pointer is NULL, exit");
        exit(1);
    }
    unsigned int addr_len = sizeof(m_peeraddr);
     
    int n;
    if (m_iptype == 4)
    {
        n = recvfrom(m_rtp_sockfd,m_pSrtpTranslator->m_pkg_buffer,MAX_PKG_LEN,0,
                     (struct sockaddr *)&m_peeraddr, &addr_len);
    }
    else
    {
        n = recvfrom(m_rtp_sockfd,m_pSrtpTranslator->m_pkg_buffer,MAX_PKG_LEN,0,
                     (struct sockaddr *)&m_peeraddr_v6, &addr_len);
    }
    if (n)
    {
        LOG(DEBUG,"%d bytes data received from peer address %s\n", n, inet_ntoa(m_peeraddr_rtcp.sin_addr));
    }
    return n;
}
void CSrtpBidirectStream::SendSRTCP(int rtcp_len)
{
    if (!m_pRtpTranslator)
    {
        LOG(ERROR,"the pRTP pointer is NULL, exit");
        exit(1);
    }
    int n;
    if (m_iptype == 4)
    {
        n = sendto(m_rtcp_sockfd,m_pRtpTranslator->m_pkg_buffer,rtcp_len,
                   0,(struct sockaddr *)&m_peeraddr_rtcp, sizeof(m_peeraddr_rtcp));
    }
    else
    {
        n = sendto(m_rtcp_sockfd,m_pRtpTranslator->m_pkg_buffer,rtcp_len,
                   0,(struct sockaddr *)&m_peeraddr_rtcp_v6, sizeof(m_peeraddr_rtcp_v6));
    }
    if (n < 0)
    {
        LOG(ERROR,"sending data failed,, error code: %d, error info: %s",errno,strerror(errno));
        exit(1);
    }
    //printf("have sent %d packages\n", n);
    LOG(DEBUG,"%d srtcp bytes data has been sent out successfully", n);
}
int CSrtpBidirectStream::ReceiveSRTCP()
{
    if (!m_pSrtpTranslator)
    {
        LOG(ERROR,"the pRTP pointer is NULL, exit");
        exit(1);
    }
    unsigned int addr_len = sizeof(m_peeraddr_rtcp);
    int n = recvfrom(m_rtcp_sockfd,m_pSrtpTranslator->m_pkg_buffer,MAX_PKG_LEN,0,
                     (struct sockaddr *)&m_peeraddr_rtcp, &addr_len);
    if(n <= 0)
    {
        LOG(ERROR,"receiving SRTCP failed");
        exit(1);
    }
    else
    {
        //printf("%d bytes received from peer address %s\n", n, inet_ntoa(m_peeraddr_rtcp.sin_addr));
        LOG(DEBUG,"%d bytes data received from peer address %s\n", n, inet_ntoa(m_peeraddr_rtcp.sin_addr));
        return n;
    }
}