This project will generate one program called "send_srtp", it's main purpose is to translate one plain rtp/rtcp pkg from the pcap file into srtp/srtcp and then send out to one NE, i.e. PCSCF with srtp-rtp interworking functionality; then the peer (sipp with rtp_echo enabled) will echo the rtp from PCSCF and PCSCF will send SRTP pkg to our program and the program will decode and validate it.

The real deployment will make use of sipp to complete the sdp negotiation, i.e. srtp related parameter. 
This project depends on libsrtp(libsrtp2) and pcap library, check the Makefile for details.


The network topology is:

UE(sipp calling send_srtp)  ------ PCSCF with media attached ---------peer (sipp with rtp_echo enabled)

------------------INVITE------------------------>

                                                ------------INVITE------------------->

                                                <----------200 ok---------------------

<-----------200 OK------------------------------

------------ACK-------------------------------->

                                                ------------ACK-----------------------> 

--------------SRTP/SRTCP media----------------->

                                                --------------RTP/RTCP---------------->

                                                <-------------RTP/RTCP-----------------  

<-----------SRTP/SRTP media---------------------                                                                                            



