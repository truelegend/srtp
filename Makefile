
all: send_srtp
.PHONY: all

send_srtp: send_srtp.o srtppkgtranslator.o srtpbidirectstream.o log.o rtpqueue.o argumentshandler.o
	g++ -o send_srtp send_srtp.o srtppkgtranslator.o srtpbidirectstream.o rtpqueue.o log.o argumentshandler.o -Wall -g -lpcap -L . -lsrtp2 -lpthread

send_srtp.o: send_srtp.h srtp.h srtpbidirectstream.h srtppkgtranslator.h rtpqueue.h log.h argumentshandler.h


srtpbidirectstream.o: srtpbidirectstream.h srtppkgtranslator.h log.h rtpqueue.h

srtppkgtranslator.o: srtp.h srtppkgtranslator.h log.h

rtpqueue.o: rtpqueue.h

log.o: log.h

argumentshandler.o: argumentshandler.h


.PHONY: clean
clean:
	rm -f *.o send_srtp
