#include "srtpbidirectstream.h"

CSrtpBidirectStream::CSrtpBidirectStream(char *local_addr,unsigned int local_port,
	char *peer_addr,unsigned int peer_port)
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
    m_rtcp_sockfd = socket(AF_INET,SOCK_DGRAM,0);
}
CSrtpBidirectStream::~CSrtpBidirectStream()
{
    LOG(DEBUG,"close rtp/rtcp socket in ~CSrtpBidirectStream");
	close(m_rtp_sockfd);
    close(m_rtcp_sockfd);
}
bool CSrtpBidirectStream::BindLocalPortforRTP()
{
	if(bind(m_rtp_sockfd,(struct sockaddr *)&m_localaddr,sizeof(struct sockaddr)) == -1)
    {
	    close(m_rtp_sockfd);
	    printf("error when trying to bind local ip/port for rtp");
	    return false;
    }
    return true;
}

bool CSrtpBidirectStream::BindLocalPortforRTCP()
{
    if(bind(m_rtcp_sockfd,(struct sockaddr *)&m_localaddr_rtcp,sizeof(struct sockaddr)) == -1)
    {
        close(m_rtcp_sockfd);
        printf("error when trying to bind local ip/port for rtcp");
        return false;
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
    int n = sendto(m_rtp_sockfd,m_pRtpTranslator->m_pkg_buffer,rtp_len,
    	0,(struct sockaddr *)&m_peeraddr, sizeof(m_peeraddr));
    LOG(DEBUG,"%d srtp bytes data has been sent out successfully", n);
    //printf("have sent %d packages\n", n);
}
int CSrtpBidirectStream::ReceiveSRTP()
{   
    if (!m_pSrtpTranslator)
    {
        LOG(ERROR,"the pRTP pointer is NULL, exit");
    	exit(1);
    }
    unsigned int addr_len = sizeof(m_peeraddr);
    int n = recvfrom(m_rtp_sockfd,m_pSrtpTranslator->m_pkg_buffer,MAX_PKG_LEN,0,
    	(struct sockaddr *)&m_peeraddr, &addr_len);
    if(n <= 0)
    {
        LOG(ERROR,"receiving SRTP failed");
    	exit(1);
    }
    else
    {
    	//printf("%d bytes received from peer address %s\n", n, inet_ntoa(m_peeraddr.sin_addr));
        LOG(DEBUG,"%d bytes data received from peer address %s", n, inet_ntoa(m_peeraddr.sin_addr));
    	return n;
    }
}
void CSrtpBidirectStream::SendSRTCP(int rtcp_len)
{   
    if (!m_pRtpTranslator)
    {
        LOG(ERROR,"the pRTP pointer is NULL, exit");
        exit(1);
    }
    int n = sendto(m_rtcp_sockfd,m_pRtpTranslator->m_pkg_buffer,rtcp_len,
        0,(struct sockaddr *)&m_peeraddr_rtcp, sizeof(m_peeraddr_rtcp));
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