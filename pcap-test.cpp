#include "pcap-test.h"

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header){
	struct ether_header *eth_hdr = (struct ether_header *)pkt_data;
	
	u_int16_t eth_type = ntohs(eth_hdr->ether_type);

	// if type is not IP, return function
	if(eth_type!=ETHERTYPE_IP) return;

	struct ip *ip_hdr = (struct ip *)(pkt_data+sizeof(ether_header)); 

	u_int8_t ip_type = ip_hdr->ip_p;
	u_int8_t ip_offset = ip_hdr->ip_hl;

	// if protocol is not tcp, then return func
	if(ip_type != 6) return;

	//if protocol is tcp, get tcp_hdr
	struct tcphdr *tcp_hdr = (struct tcphdr*)(pkt_data+sizeof(ether_header)+ip_offset*4);

	unsigned short tcp_offset = tcp_hdr->doff;

	printf("\nPacket Info ====================================\n");

	// print pkt length
    printf("%u bytes captured\n", header->caplen);

	// print mac addr
	u_int8_t *dst_mac = eth_hdr->ether_dhost;
	u_int8_t *src_mac = eth_hdr->ether_shost;

	printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
		dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
	printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
		src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
	
	//print ip addr
	char src_ip[16], dst_ip[16];
	char* tmp = inet_ntoa(ip_hdr->ip_src);
	strcpy(src_ip, tmp);
	tmp = inet_ntoa(ip_hdr->ip_dst);
	strcpy(dst_ip, tmp);

	printf("Src IP : %s\n", src_ip);
	printf("Dst IP : %s\n", dst_ip);

	//print port
	unsigned short src_port = ntohs(tcp_hdr->source);
	unsigned short dst_port = ntohs(tcp_hdr->dest);

	printf("Src Port : %d\n", src_port);
	printf("Dst Port : %d\n", dst_port);

	// print payload
	u_int32_t payload_len = header->caplen - sizeof(ether_header) - ip_offset*4 - tcp_offset*4;
	u_int32_t max = payload_len >= 16 ? 16 : payload_len;
	const u_char* pkt_payload = pkt_data+sizeof(ether_header)+ip_offset*4+tcp_offset*4;

	printf("Payload : ");

	if(!payload_len){
		printf("No payload\n");
	}else{
		for(int i=0;i<max;i++) printf("%02x ", *(pkt_payload+i));
		printf("\n");
	}
}
