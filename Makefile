#g++ -o receive_msrp receive_msrp.cpp 
#g++ -o send_msrp send_msrp.cpp CMsrpChunk.cpp -lssl -lcrypto


all: send_srtp
.PHONY: all

send_srtp: send_srtp.o srtppkgtranslator.o srtpbidirectstream.o log.o
	g++ -o send_srtp send_srtp.o srtppkgtranslator.o srtpbidirectstream.o log.o -lpcap -L . -lsrtp2 -lpthread

send_srtp.o: send_srtp.h srtp.h srtpbidirectstream.h srtppkgtranslator.h log.h


srtpbidirectstream.o: srtpbidirectstream.h srtppkgtranslator.h log.h

srtppkgtranslator.o: srtp.h srtppkgtranslator.h log.h

log.o: log.h


.PHONY: clean
clean:
	rm -f *.o send_srtp
