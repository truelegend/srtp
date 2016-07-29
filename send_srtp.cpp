#include "send_srtp.h"


struct timeval pre_time;
struct timeval cur_time;

unsigned int sent_rtp_num  = 0;
unsigned int sent_rtcp_num = 0;
unsigned int recv_rtp_num  = 0;
unsigned int recv_rtcp_num = 0;

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

CArgumentsHandler::CArgumentsHandler(int argc, char **argv)
{
    m_argc = argc;
    m_argv = argv;
    m_cipher_key_len = 0;
}
bool CArgumentsHandler::VerifyArguments()
{
    if(m_argc != 10)
    {
        printf("the arguments number is wrong\n");
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
        printf("unsupported enc type\n");
        Usage();
        return false;
    }
    m_auth_type = atoi(m_argv[7]);
    if (m_auth_type != 80 && m_auth_type != 32)
    {
        printf("unsupported authentication type\n");
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
    return true;
}
bool CArgumentsHandler::IsBase64keyCorrect(const char *str)
{
    switch (strlen(str))
    {
        case 64:
            if (m_enc_type != 256)
            {
                printf("wrong key len for aes256!\n");
                return false;
            }            
            break;
        case 40:
            if (m_enc_type != 128)
            {
                printf("wrong key len for ase128\n");
                return false;
            }
            break;
    }
    return true;
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
    u_short port = ntohs(*(u_short*) (pkt_data+14+20));
    isRTCP = (port%2==0)?false:true;
    LOG(DEBUG,"the port number is %d, isRTCP is %d", port, isRTCP);

    int pkg_app_len = header->len-42;  // 42 = 14 mac + 20 ip hdr + 8 udp hdr
    int orig_pkg_app_len = pkg_app_len;
    memcpy(p_stream->m_pRtpTranslator->m_pkg_buffer,pkt_data+14+20+8,orig_pkg_app_len);
    //printf("pkg_app_len is :%d before protection\n", pkg_app_len);
    // need to input the whole rtp pkg len, not just the payload
    if (isRTCP)
    {
        LOG(DEBUG,"start to encode rtcp");
        p_stream->m_pRtpTranslator->EncodeRTCP(&pkg_app_len);
    }
    else
    {
        LOG(DEBUG,"start to encode rtp");
        p_stream->m_pRtpTranslator->EncodeRTP(&pkg_app_len);
    }
    
    //printf("pkg_app_len is :%d after protection\n", pkg_app_len);
    if (!isRTCP)
    {
        LOG(DEBUG,"for sent srtp, we'll cache the original rtp pkg");
        pthread_mutex_lock(&g_mutex);   
        int rear = p_stream->m_rtpque.EnQueue(pkt_data+14+20+8,orig_pkg_app_len);
        pthread_mutex_unlock(&g_mutex);     
        LOG(DEBUG,"the enqueued rear is %d", rear);
    }
    if(sent_rtp_num == 0)
    {
        if(isRTCP)
        {
            LOG(DEBUG,"send srtcp");
            p_stream->SendSRTCP(pkg_app_len);
            sent_rtcp_num++;
        }
        else
        {
            LOG(DEBUG,"send srtp");
            p_stream->SendSRTP(pkg_app_len);
            sent_rtp_num++; 
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
	        sent_rtcp_num++;
        }
        else
        {
            LOG(DEBUG,"send srtp");
            p_stream->SendSRTP(pkg_app_len);
	        sent_rtp_num++;
        }        
        pre_time = cur_time;
    }
    LOG(DEBUG,"this is the %d srtp sent out, %d srtcp sent out", sent_rtp_num,sent_rtcp_num);
}
u_short GetRtpSeq(u_char *pRTP)
{
    u_short seq = ntohs(*((u_short*)(pRTP+2)));
    return seq;
}
void* ReceiveSrtpThread(void *p)
{
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
        recv_rtp_num++;
        LOG(DEBUG,"this is the %d srtp received", recv_rtp_num);
        int spkg_app_len = recv_spkg_app_len;

        p_stream->m_pSrtpTranslator->DecodeSRTP(&spkg_app_len);
        LOG(DEBUG,"the decoded srtp length is %d", spkg_app_len);
        u_short seq = GetRtpSeq(p_stream->m_pSrtpTranslator->m_pkg_buffer);
        LOG(DEBUG,"the received seq is %d", seq);
        pthread_mutex_lock(&g_mutex);   
        RAW_RTP *pStructRTP = p_stream->m_rtpque.DeQueue();
        if (!pStructRTP)
        {
            LOG(ERROR, "failed to get rtp from queue, abnormal exit");
            exit(1);
        }        
        while(spkg_app_len != pStructRTP->pkg_len)
        {
            p_stream->m_rtpque.FreeCachedRTP(pStructRTP); // destroy the useless head in case memory leak
            LOG(WARNING,"the cached rtp length is not equal to the decoded one, get the next element until they are equal");
            pStructRTP = p_stream->m_rtpque.DeQueue();
            if (!pStructRTP)
            {
                LOG(WARNING, "failed to get rtp from queue, abnormal exit");
                exit(1);
            }
        }   
        // check if the rtp sequence is equal 
        while(seq > GetRtpSeq(pStructRTP->p_pkg))
        {
            LOG(WARNING,"the cached rtp seq is smaller than the decoded one, there must be pkg loss, to get the next one from queue");
            p_stream->m_rtpque.FreeCachedRTP(pStructRTP); // destroy the useless head in case memory leak
            pStructRTP = p_stream->m_rtpque.DeQueue();
            if (!pStructRTP)
            {
                LOG(WARNING, "failed to get rtp from queue, abnormal exit");
                exit(1);
            }
        }
        LOG(DEBUG,"now we can compare the two pkg since the length and seq are all equal");
        if (CompareMem(pStructRTP->p_pkg,p_stream->m_pSrtpTranslator->m_pkg_buffer,spkg_app_len))
        {
            LOG(DEBUG,"succesfully encode&decode, well done!\n");
            p_stream->m_rtpque.FreeCachedRTP(pStructRTP);
            pthread_mutex_unlock(&g_mutex); 
        }
        else
        {
            LOG(ERROR,"the comparing failed, there must be something wrong in encoding or decoding");
            p_stream->m_rtpque.FreeCachedRTP(pStructRTP);
            pthread_mutex_unlock(&g_mutex); 
            exit(1);
        }    
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
        argumentsHandler.m_peer_addr,argumentsHandler.m_peer_port);
    bidstream.m_pSrtpTranslator = &srtp_tranlator;
    bidstream.m_pRtpTranslator  = &rtp_tranlator;

    bzero(&pre_time,sizeof(pre_time));
    bzero(&cur_time,sizeof(cur_time));

    if(!bidstream.BindLocalPortforRTP())
    {
        printf("binding local rtp failed\n");
        LOG(ERROR,"binding local rtp failed");
        exit(1);
    }
      if(!bidstream.BindLocalPortforRTCP())
    {
        printf("binding local rtcp failed\n");
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
    pcap_t *fp;
    const char *filename = argumentsHandler.m_pcap_file;
    char errbuf[50];
    if ((fp = pcap_open_offline(filename, errbuf)) == NULL)
    {
        printf("unable to open pcap file");
        LOG(ERROR,"unable to open pcap file");
        exit(1);
    }
    else
    { 
        LOG(DEBUG,"start to handle pcap file, into loop");
    	pcap_loop(fp, 0, dispatcher_handler, (u_char* )&bidstream);
    }
    // we have to wait sometime in case the last srtp pkg can be received by the receiving thread
    //usleep(100000);
    assert(pthread_join(thd_receiver,NULL) == 0);
    LOG(DEBUG,"now the receiving rtp thread is confirmed terminated, so the main thread will exit soon");
    pcap_close(fp);
    CSrtppkgTranslator::DeInitSrtpLib();
    printf("all done, total sent rtp pkg: %d, sent rtcp pkg: %d, received rtp pkg: %d\n", sent_rtp_num, sent_rtcp_num, recv_rtp_num);
    LOG(DEBUG,"all done, total sent rtp pkg: %d, sent rtcp pkg: %d, received rtp pkg: %d", sent_rtp_num, sent_rtcp_num, recv_rtp_num);
}

//256
//zhPzQN8NAro6wnkJKryTKadITRi2Ux/zE2/0ZoL2AICspE44XKU09e3+2Dhytw==
//ce13f340df0d02ba3ac279092abc9329a7484d18b6531ff3136ff46682f60080aca44e385ca534f5edfed83872b7

//128 
//ktIfwrwAG6VaumKST+mdORiAs0wZH+NR5jZbyWKw
//92d21fc2bc001ba55aba62924fe99d391880b34c191fe351e6365bc962b0
