#ifndef _RTP_QUEUE_H
#define _RTP_QUEUE_H

#include "log.h"
#define MAX_CACHED_RTP_NUM 340
struct RAW_RTP
{
    int pkg_len;
    u_char* p_pkg;
};
class CRtpQueue
{
public:
    CRtpQueue();
    ~CRtpQueue();
    int EnQueue(const unsigned char *p, int len);
    RAW_RTP* DeQueue();
    void FreeCachedRTP(RAW_RTP *p);
    //RAW_RTP* GetHeadOfQueue();
    inline bool IsFull() {
        return (capacity >= MAX_CACHED_RTP_NUM)?true:false;
    };
    inline bool IsEmpty() {
        return (capacity == 0)?true:false;
    };


private:

    int capacity;
    int rear;
    int head;
    RAW_RTP m_raw_rtp_array[MAX_CACHED_RTP_NUM];
    
};

#endif
