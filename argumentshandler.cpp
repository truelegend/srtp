#include "argumentshandler.h"

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
    if(m_argc != 10)
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

void CArgumentsHandler::Usage()
{
    printf("usage:\n");
    printf("%s pcap_file_name src_ip src_port dst_ip dst_port 256 80 sent_key received_key\n", m_argv[0]);

}

