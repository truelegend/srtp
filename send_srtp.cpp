#include "send_srtp.h"
#include <map>
#include "rtpqueue.h"
using namespace std;

struct timeval pre_time;
struct timeval cur_time;

unsigned int g_sent_rtp_num        = 0;
unsigned int g_sent_rtcp_num       = 0;
unsigned int g_recv_rtp_num        = 0;
unsigned int g_recv_rtcp_num       = 0;
unsigned int g_error_recv_rtp_num  = 0;
unsigned int g_correct_recv_rtp_num  = 0;
unsigned int g_outorder_recv_rtp_num  = 0;
unsigned int g_recv_rtp_loss_num   =0;

static u_short g_start_seq  =    65500;
int g_mac_length = 0;

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

CArgumentsHandler::CArgumentsHandler(int argc, char **argv)
{
    m_argc = argc;
    m_argv = argv;
    m_cipher_key_len = 0;
    LOG(DEBUG,"PRINT THE MAIN ARGUMENTS");
    for(int i=0; i< m_argc; i++)
    {
        LOG(DEBUG,"%d: %s", i, m_argv[i]);
    }
}
bool CArgumentsHandler::VerifyArguments()
{
    if(m_argc != 11)
    {
        LOG(ERROR,"the arguments number is wrong");
        Usage();
        return false;
    }
    m_pcap_file = m_argv[1];
    m_local_addr = m_argv[2];
    m_local_port = atoi(m_argv[3]);
    m_peer_addr = m_argv[4];
    m_peer_port = atoi(m_argv[5]);
    m_enc_type = atoi(m_argv[6]);
    if(m_enc_type != 128 && m_enc_type != 256)
    {
        LOG(ERROR,"unsupported enc type");
        Usage();
        return false;
    }
    m_auth_type = atoi(m_argv[7]);
    if (m_auth_type != 80 && m_auth_type != 32)
    {
        LOG(ERROR,"unsupported auth type");
        Usage();
        return false;
    }
    m_local_base64_key = m_argv[8];
    if (!IsBase64keyCorrect(m_local_base64_key))
    {
        return false;
    }
    m_peer_base64_key = m_argv[9];
    if (!IsBase64keyCorrect(m_peer_base64_key))
    {
        return false;
    }
    m_iptype = atoi(m_argv[10]);
    return true;
}
bool CArgumentsHandler::IsBase64keyCorrect(const char *str)
{
    switch (strlen(str))
    {
    case 64:
        if (m_enc_type != 256)
        {
            LOG(ERROR,"wrong key len for aes256");
            return false;
        }
        break;
    case 40:
        if (m_enc_type != 128)
        {
            LOG(ERROR,"wrong key len for aes128");
            return false;
        }
        break;
    }
    return true;
}
int GetMacLengthFromPcapfile(const char* filename)
{
    fstream file;
    file.open(filename);
    if (!file)
    {
        LOG(ERROR,"failed to open pcap file");
        exit(1);
    }
    pcap_file_header pcaphdr;
    file.read((char*)&pcaphdr,sizeof(pcaphdr));
    file.close();
    LOG(DEBUG,"the link type of pcap file is: %d", pcaphdr.linktype);
    switch(pcaphdr.linktype)
    {
    case 1:
        return 14;
    case 113:
        return 16;
    default:
        LOG(ERROR,"unsupported link type");
        exit;
    }
}
void CArgumentsHandler::Usage()
{
    printf("usage:\n");
    printf("%s pcap_file_name src_ip src_port dst_ip dst_port 256 80 sent_key received_key\n", m_argv[0]);

}
bool CompareMem(const unsigned char *dst, const unsigned char *src, int len)
{
    int i = 0;
    while(i<len)
    {
        if (*dst++ == *src++)
            i++;
        else
            return false;
    }
    return true;
}
void SetRtpSeq(u_char *pRTP)
{
    *(u_short*)(pRTP+2) = htons(g_start_seq);
    g_start_seq++;
}
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    bool isRTCP;
    assert(temp1 != NULL);
    CSrtpBidirectStream *p_stream = (CSrtpBidirectStream *)temp1;
    if(header->caplen != header->len)
    {
        LOG(ERROR,"this captured pkg length is not equal with the actual real pkg length!");
        return;
    }
    u_short port = ntohs(*(u_short*) (pkt_data+g_mac_length+20));
    isRTCP = (port%2==0)?false:true;
    LOG(DEBUG,"the port number is %d, isRTCP is %d", port, isRTCP);

    int pkg_app_len = header->len-g_mac_length-20-8;  // 42 = 14 mac + 20 ip hdr + 8 udp hdr
    int orig_pkg_app_len = pkg_app_len;
    memcpy(p_stream->m_pRtpTranslator->m_pkg_buffer,pkt_data+g_mac_length+20+8,orig_pkg_app_len);
    //printf("pkg_app_len is :%d before protection\n", pkg_app_len);
    // need to input the whole rtp pkg len, not just the payload
    if (isRTCP)
    {
        LOG(DEBUG,"start to encode rtcp");
        p_stream->m_pRtpTranslator->EncodeRTCP(&pkg_app_len);
    }
    else
    {
        //LOG(DEBUG,"start to set rtp sequence");
        //SetRtpSeq(p_stream->m_pRtpTranslator->m_pkg_buffer);
        LOG(DEBUG,"start to encode rtp");
        p_stream->m_pRtpTranslator->EncodeRTP(&pkg_app_len);
        u_short seq_queue = GetRtpSeq(p_stream->m_pRtpTranslator->m_pkg_buffer);
        LOG(DEBUG,"for sent srtp, we'll cache the original rtp pkg, seq is %d", seq_queue);
        pthread_mutex_lock(&g_mutex);
        int rear = p_stream->m_rtpque.EnQueue(pkt_data+g_mac_length+20+8,orig_pkg_app_len);
        pthread_mutex_unlock(&g_mutex);
        LOG(DEBUG,"the enqueued rear is %d", rear);
    }
    //printf("pkg_app_len is :%d after protection\n", pkg_app_len);

    if(g_sent_rtp_num == 0)
    {
        if(isRTCP)
        {
            LOG(DEBUG,"send srtcp");
            p_stream->SendSRTCP(pkg_app_len);
            g_sent_rtcp_num++;
        }
        else
        {
            LOG(DEBUG,"send srtp");
            p_stream->SendSRTP(pkg_app_len);
            g_sent_rtp_num++;
        }
        pre_time = header->ts;
    }
    else
    {
        cur_time = header->ts;
        unsigned int interval = (cur_time.tv_sec - pre_time.tv_sec) * 1000 * 1000 + (cur_time.tv_usec - pre_time.tv_usec);
        usleep(interval);
        if (isRTCP)
        {
            LOG(DEBUG,"send srtcp");
            p_stream->SendSRTCP(pkg_app_len);
            g_sent_rtcp_num++;
        }
        else
        {
            LOG(DEBUG,"send srtp");
            p_stream->SendSRTP(pkg_app_len);
            g_sent_rtp_num++;
        }
        pre_time = cur_time;
    }
    LOG(DEBUG,"this is the %d srtp sent out, %d srtcp sent out", g_sent_rtp_num,g_sent_rtcp_num);
}
u_short GetRtpSeq(const u_char *pRTP)
{
    u_short seq = ntohs(*((u_short*)(pRTP+2)));
    return seq;
}
void BuildCachedRTPStruct(RAW_RTP *dst_rawrtp,const RAW_RTP* src_rawrtp)
{
    dst_rawrtp->pkg_len = src_rawrtp->pkg_len;
    dst_rawrtp->p_pkg = new u_char[dst_rawrtp->pkg_len];
    if (!dst_rawrtp->p_pkg)
    {
        LOG(ERROR,"failed to allocate memmory");
        exit;
    }
    memcpy(dst_rawrtp->p_pkg,src_rawrtp->p_pkg,dst_rawrtp->pkg_len);
}
void* ReceiveSrtpThread(void *p)
{   //return NULL;
    map<u_short, RAW_RTP> map_recv_cache;
    CSrtpBidirectStream *p_stream = (CSrtpBidirectStream *)p;
    while(1)
    {
        int recv_spkg_app_len = p_stream->ReceiveSRTP();
        if (recv_spkg_app_len == -1)
        {
            LOG(WARNING,"timeout timer triggered, terminate the receiving thread");
            break;
        }
        LOG(DEBUG,"have received %d bytes succesfully", recv_spkg_app_len);
        g_recv_rtp_num++;
        LOG(DEBUG,"this is the %d srtp received", g_recv_rtp_num);
        int spkg_app_len = recv_spkg_app_len;
        p_stream->m_pSrtpTranslator->DecodeSRTP(&spkg_app_len);
        u_short seq = GetRtpSeq(p_stream->m_pSrtpTranslator->m_pkg_buffer);
        LOG(DEBUG,"the received rtp seq is %d", seq);
        map<u_short,RAW_RTP>::iterator it = map_recv_cache.find(seq);
        if (it != map_recv_cache.end())
        {
            g_outorder_recv_rtp_num++;
            if (spkg_app_len == it->second.pkg_len 
                && CompareMem(it->second.p_pkg,p_stream->m_pSrtpTranslator->m_pkg_buffer,spkg_app_len))
            {
                LOG(DEBUG,"out-of-order: seq %d succesfully encode&decode, well done!\n", seq);
                g_correct_recv_rtp_num++;
            }
            else
            {
                LOG(ERROR,"out-of-order: seq %d the comparing failed, there must be something wrong in encoding or decoding\n", seq);
                g_error_recv_rtp_num++;
            }
            //p_stream->m_rtpque.FreeCachedRTP(&it->second);
            delete[] it->second.p_pkg;
            map_recv_cache.erase(it);
            continue;
        }
        pthread_mutex_lock(&g_mutex);
        RAW_RTP *pStructRTP = p_stream->m_rtpque.DeQueue();
        if (!pStructRTP)
        {
            LOG(ERROR, "failed to get rtp head from queue, abnormal exit");
            exit(1);
        }
        // check if the rtp sequence is equal
        u_short seq_queue = GetRtpSeq(pStructRTP->p_pkg);
        while(seq > seq_queue)
        {
            LOG(WARNING,"the cached sent rtp seq is smaller, put it into recv rtp cache map firstly");
            RAW_RTP rawrtp;
            BuildCachedRTPStruct(&rawrtp,pStructRTP);
            map_recv_cache.insert(map<u_short,RAW_RTP>::value_type(seq_queue,rawrtp));
            p_stream->m_rtpque.FreeCachedRTP(pStructRTP);
            pStructRTP = p_stream->m_rtpque.DeQueue();//   GetHeadOfQueue();
            if (!pStructRTP)
            {
                LOG(ERROR, "failed to get rtp from queue, abnormal exit");
                exit(1);
            }
            seq_queue = GetRtpSeq(pStructRTP->p_pkg);
        }
        if(seq != seq_queue)
        {
            LOG(ERROR,"seq: %d != seq_queue: %d, there should not happen", seq, seq_queue);
            p_stream->m_rtpque.FreeCachedRTP(pStructRTP);
            pthread_mutex_unlock(&g_mutex);
            exit(1);
        }
        LOG(DEBUG,"now we can compare the two pkg since the length and seq are all equal");
        if (spkg_app_len == pStructRTP->pkg_len
            && CompareMem(pStructRTP->p_pkg,p_stream->m_pSrtpTranslator->m_pkg_buffer,spkg_app_len))
        {
            LOG(DEBUG,"succesfully encode&decode, well done!\n");
            g_correct_recv_rtp_num++;
        }
        else
        {
            LOG(ERROR,"the comparing failed, there must be something wrong in encoding or decoding");
            g_error_recv_rtp_num++;
            //exit(1);
        }
        p_stream->m_rtpque.FreeCachedRTP(pStructRTP);
        pthread_mutex_unlock(&g_mutex);    
    }
    g_recv_rtp_loss_num = map_recv_cache.size();
    LOG(WARNING,"the map size (the lost pkg) is %d",g_recv_rtp_loss_num);
    for (map<u_short,RAW_RTP>::iterator it = map_recv_cache.begin(); it != map_recv_cache.end(); ++it)
    {
        //p_stream->m_rtpque.FreeCachedRTP(&it->second);
        delete[] it->second.p_pkg;
    }
    LOG(WARNING,"the rtp receiving thread exits");
}
int main(int argc, char **argv)
{
    CArgumentsHandler argumentsHandler(argc,argv);
    if (!argumentsHandler.VerifyArguments())
    {
        exit(1);
    }
    LOG(DEBUG,"arguments verification passes");
    CSrtppkgTranslator::InitSrtpLib();
    CSrtppkgTranslator rtp_tranlator(argumentsHandler.m_enc_type, argumentsHandler.m_auth_type,
                                     RTP, argumentsHandler.m_local_base64_key);
    CSrtppkgTranslator srtp_tranlator(argumentsHandler.m_enc_type, argumentsHandler.m_auth_type,
                                      SRTP, argumentsHandler.m_peer_base64_key);

    CSrtpBidirectStream bidstream(argumentsHandler.m_local_addr,argumentsHandler.m_local_port,
                                  argumentsHandler.m_peer_addr,argumentsHandler.m_peer_port,argumentsHandler.m_iptype);
    bidstream.m_pSrtpTranslator = &srtp_tranlator;
    bidstream.m_pRtpTranslator  = &rtp_tranlator;

    bzero(&pre_time,sizeof(pre_time));
    bzero(&cur_time,sizeof(cur_time));

    if(!bidstream.BindLocalPortforRTP())
    {
        LOG(ERROR,"binding local rtp failed");
        exit(1);
    }
    if(!bidstream.BindLocalPortforRTCP())
    {
        LOG(ERROR,"binding local rtcp failed");
        exit(1);
    }
    pthread_t thd_receiver;
    int ret = pthread_create(&thd_receiver,NULL,ReceiveSrtpThread,&bidstream);
    if (ret)
    {
        LOG(ERROR,"failed to create receiving thread, error No. is %d", ret);
        exit(1);
    }
    const char *filename = argumentsHandler.m_pcap_file;
    g_mac_length = GetMacLengthFromPcapfile(filename);
    pcap_t *fp;
    char errbuf[50];
    if ((fp = pcap_open_offline(filename, errbuf)) == NULL)
    {
        LOG(ERROR,"unable to open pcap file");
        exit(1);
    }
    else
    {
        LOG(DEBUG,"start to handle pcap file, into loop");
        pcap_loop(fp, 0, dispatcher_handler, (u_char* )&bidstream);
    }
    pcap_close(fp);
    LOG(DEBUG,"all the pkg in the pcap file have been sent out successfully");
    // we have to wait sometime in case the last srtp pkg can be received by the receiving thread
    //usleep(100000);
    if(pthread_join(thd_receiver,NULL) != 0)
    {
        LOG(ERROR,"the main thread will wait until the receiving thread exits, but seems it doesn't");
    }
    LOG(DEBUG,"now the receiving rtp thread is confirmed terminated, so the main thread will exit soon");
    CSrtppkgTranslator::DeInitSrtpLib();
    if (g_recv_rtp_loss_num != (g_sent_rtp_num - g_recv_rtp_num))
    {
        LOG(ERROR,"the calculated lost rtp number is not equal, %d:%d, if rtp sendqueue is ever full, then this is OK",g_recv_rtp_loss_num,g_sent_rtp_num-g_recv_rtp_num);
    }
    LOG(DEBUG,"all done! sent rtp pkg: %d, sent rtcp pkg: %d, received rtp pkg: %d, successfuly compared rtp pkg: %d, failed compared rtp pkg: %d, out-of-order srtp pkg: %d, lost srtp pkg: %d",
        g_sent_rtp_num, g_sent_rtcp_num, g_recv_rtp_num, g_correct_recv_rtp_num, g_error_recv_rtp_num, g_outorder_recv_rtp_num, g_sent_rtp_num - g_recv_rtp_num);
}

//256
//zhPzQN8NAro6wnkJKryTKadITRi2Ux/zE2/0ZoL2AICspE44XKU09e3+2Dhytw==
//ce13f340df0d02ba3ac279092abc9329a7484d18b6531ff3136ff46682f60080aca44e385ca534f5edfed83872b7

//128
//ktIfwrwAG6VaumKST+mdORiAs0wZH+NR5jZbyWKw
//92d21fc2bc001ba55aba62924fe99d391880b34c191fe351e6365bc962b0
