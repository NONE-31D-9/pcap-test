#ifndef PCAP_TEST_H_
#define PCAP_TEST_H_

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <cstdio>
#include <cstring>
#include <pcap.h>


void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header);

#endif
