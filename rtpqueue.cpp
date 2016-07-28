#include "rtpqueue.h"
CRtpQueue::CRtpQueue()
{
    
}
CRtpQueue::~CRtpQueue()
{
 
}
int CRtpQueue::EnQueue(char *p, int len)
{
	m_raw_rtp_array[rear].p_pkg = new char[len];
	memcyp(m_raw_rtp_array[rear].p_pkg,p,len);
	m_raw_rtp_array[rear].pkg_len = len;
}