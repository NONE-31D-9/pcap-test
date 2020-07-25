all: pcap-test

pcap-test:
	g++ -o pcap-test main.cpp pcap-test.cpp -lpcap

clean:
	rm -f pcap-test *.o
