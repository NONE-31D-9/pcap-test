#ifndef PCAP_TEST_H_
#define PCAP_TEST_H_

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <cstdio>


void dump_pkt(const u_char *pkt_data);
void dump_eth_hdr(const u_char *pkt_data);
void dump_tcp_hdr(const u_char *pkt_data);
void dump_data(const u_char *pkt_data);

#endif
