#include "rtpqueue.h"
CRtpQueue::CRtpQueue()
{
    capacity = 0;
    rear   = -1;
    head  = 0;
    memset(m_raw_rtp_array, 0x0, sizeof(m_raw_rtp_array));
}
CRtpQueue::~CRtpQueue()
{
    for(int i=0; i<MAX_CACHED_RTP_NUM; i++)
    {
    	delete [] m_raw_rtp_array[i].p_pkg;
    }
}
int CRtpQueue::EnQueue(const unsigned char *p, int len)
{
	if (IsFull())
	{
		LOG(WARNING,"the queue is full and cannot enqueue any element");
		return -1;
	}
	rear = (rear+1)%MAX_CACHED_RTP_NUM;
	m_raw_rtp_array[rear].p_pkg = new u_char[len];
	if (!m_raw_rtp_array[rear].p_pkg)
	{
		LOG(WARNING,"failed to allocate new memory");
		return -1;
	}
	memcpy(m_raw_rtp_array[rear].p_pkg,p,len);
	m_raw_rtp_array[rear].pkg_len = len;
	capacity++;
	return rear;
}
RAW_RTP* CRtpQueue::DeQueue()
{
	if (IsEmpty())
	{
		LOG(WARNING,"the queue is empty, this should not happen--failed to enqueue or multi-thread conflict?");
		return NULL;
	}
    int old_head = head;
    capacity--;
    head = (head+1)%MAX_CACHED_RTP_NUM;
    LOG(DEBUG,"Have got the head of the queue: %d", old_head);
    return &m_raw_rtp_array[old_head];
}
void CRtpQueue::FreeCachedRTP(RAW_RTP *p)
{
	LOG(DEBUG,"free the memory for RAW_RTP");
	delete [] p->p_pkg;
	p->pkg_len = 0;
}