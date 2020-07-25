#include "pcap-test.h"

void dump_pkt(const u_char *pkt_data){
	printf("include success\n");	
	dump_eth_hdr(pkt_data);

}


void dump_eth_hdr(const u_char *pkt_data){

}

void dump_tcp_hdr(const u_char *pkt_data);
void dump_data(const u_char *pkt_data);
