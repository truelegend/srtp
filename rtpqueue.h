#ifndef _RTP_QUEUE_H
#define _RTP_QUEUE_H

#include "log.h"
#define CACHED_RTP_NUM 5
struct RAW_RTP
{
    int pkg_len;
    char* p_pkg;
};
class CRtpQueue
{
    public:
    	CRtpQueue();
        ~CRtpQueue();
        int EnQueue(char *p, int len);
        int DeQueue();
        

    private:
        
        int m_size;
        int rear;
        int front;
        RAW_RTP m_raw_rtp_array[CACHED_RTP_NUM];

};

#endif
