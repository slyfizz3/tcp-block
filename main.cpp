#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>
#include <pcap.h>
#include <sys/ioctl.h> 
#include <net/if.h>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#define ETH_HLEN 14
#define TCPPROTO_HTTP 80
#define TCPPROTO_HTTPS 443

using namespace std;

#pragma pack(push, 1)
struct TcpForward{
    EthHdr ethHdr;
    IpHdr ipHdr;
    TcpHdr tcpHdr;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct TcpBackward{
    EthHdr ethHdr;
    IpHdr ipHdr;
    TcpHdr tcpHdr;
    char msg[56] = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
};

#pragma pack(pop)

Mac get_mac_addr(char* interface){
    string path=interface;
    ifstream fp ("/sys/class/net/" + path + "/address");
    string macaddr;
    fp >> macaddr;
    fp.close();
    return Mac(macaddr);
}

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"");
}

struct TcpForward set_ForWard(struct EthHdr * eth,struct IpHdr * ip,struct TcpHdr * tcp,int payload_len,Mac mymac){
	 struct TcpForward tFW;
	 tFW.ethHdr = *eth;
         tFW.ipHdr = *ip;
         tFW.tcpHdr = *tcp;

         tFW.ethHdr.smac_ = mymac;

         tFW.ipHdr.tot_len = htons(40);
         tFW.ipHdr.ttl = 128;
         tFW.ipHdr.check = 0;

         tFW.tcpHdr.th_off = 5;
         tFW.tcpHdr.th_flags = TH_RST | TH_ACK;
         tFW.tcpHdr.th_seq = htonl(ntohl(tcp->th_seq) + payload_len);
         tFW.tcpHdr.th_ack = tcp->th_ack;
         tFW.tcpHdr.th_sum = 0;
         
         return tFW;
}
struct TcpBackward set_BackWard(struct EthHdr * eth,struct IpHdr * ip,struct TcpHdr * tcp,int payload_len){
	struct TcpBackward tBW;
 	tBW.ethHdr = *eth;
        tBW.ipHdr = *ip;
        tBW.tcpHdr = *tcp;

        tBW.ethHdr.smac_ = eth->dmac_;

        tBW.ipHdr.dip_ = ip->sip_;
        tBW.ipHdr.sip_ = ip->dip_;
        tBW.ipHdr.tot_len = htons(40 + 56);
        tBW.ipHdr.ttl = 128;
        tBW.ipHdr.check = 0;

        tBW.tcpHdr.th_off = 5;
        tBW.tcpHdr.th_sport = tcp->th_dport;
        tBW.tcpHdr.th_dport = tcp->th_sport;
        tBW.tcpHdr.th_flags = TH_FIN | TH_ACK;
        tBW.tcpHdr.th_seq = tcp->th_ack;
        tBW.tcpHdr.th_ack = htonl(htonl(tcp->th_seq) + payload_len);
        tBW.tcpHdr.th_sum = 0;
        return tBW;
}

uint16_t calc_checksum(void* pkt, int size)
{
    uint16_t * buf = (uint16_t *) pkt;
    unsigned int res = 0;

    while(size > 1)
    {
        res += *buf;
        buf++;
        size -= sizeof(uint16_t);
    }

    if(size) 
        res += *buf;
    
    while( res >> 16 )
        res = (res & 0xFFFF) + (res >> 16);

    res = ~res;

    return (uint16_t(res));
}

uint16_t tcp_checksum(void* pkt, Pseudoheader pseudo)
{
    uint16_t pse = ~calc_checksum(&pseudo, sizeof(Pseudoheader));
    uint16_t tcp = ~calc_checksum(pkt, htons(pseudo.tcp_len));

    unsigned int res = pse + tcp;
    
    while( res >> 16 )
        res = (res & 0xFFFF) + (res >> 16); 
    
    res = ~res;

    return (uint16_t(res));
}


void set_pseudoFW(struct TcpForward FW){
 	pseudoForward.dip = FW.ipHdr.dip_;
        pseudoForward.sip = FW.ipHdr.sip_;
        pseudoForward.protocol = IPPROTO_TCP;
        pseudoForward.tcp_len = htons(20);
}

void set_pseudoBW(struct TcpBackward BW){
	pseudoBackward.dip = BW.ipHdr.dip_;
        pseudoBackward.sip = BW.ipHdr.sip_;
        pseudoBackward.protocol = IPPROTO_TCP;
        pseudoBackward.tcp_len = htons(20 + 56);
}




int main(int argc, char* argv[])
{
    if(argc!=3){
        usage();
        return -1;
    }

    string dev = argv[1];
    string pattern = argv[2];

    Mac mymac = get_mac_addr(argv[1]);
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev.c_str(), errbuf);
		return -1;
	}

	while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            cout << "pcap_next_ex return "<<res<<'('<<pcap_geterr(handle)<<')'<<endl;
            break;
        }

        EthHdr * eth = (EthHdr *) packet;
        if(ntohs(eth->type_) != EthHdr::Ip4) continue;    // ipv4 check
        IpHdr * ip = (IpHdr *)(packet + ETH_HLEN);
        if(ip->protocol != IPPROTO_TCP) continue;   // tcp check
        
        uint32_t IP_HLEN = ip->ihl * 4;
        TcpHdr * tcp = (TcpHdr *)((char *)ip + IP_HLEN);
        
        if(ntohs(tcp->th_dport) != TCPPROTO_HTTP && ntohs(tcp->th_dport) != TCPPROTO_HTTPS) continue;

        uint32_t TCP_HLEN = tcp->th_off * 4;
        char *payload = (char *)((char*)tcp + TCP_HLEN);
        uint32_t payload_len = ntohs(ip->tot_len) - IP_HLEN - TCP_HLEN;
        
        if( string(payload, payload_len).find(pattern) != string::npos){
            //detect target pattern
            
            struct TcpForward FW;
            struct TcpBackward BW;
            
            FW=set_ForWard(eth,ip,tcp,payload_len,mymac);
            BW=set_BackWard(eth,ip,tcp,payload_len);

            FW.ipHdr.check = calc_checksum(&FW.ipHdr, 20);
            BW.ipHdr.check = calc_checksum(&BW.ipHdr, 20);

            set_pseudoFW(FW);
            set_pseudoBW(BW);
         
            FW.tcpHdr.th_sum = tcp_checksum(&(FW.tcpHdr), pseudoForward);
            BW.tcpHdr.th_sum = tcp_checksum(&(BW.tcpHdr), pseudoBackward);

            int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&FW), sizeof(FW));
            int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&BW), sizeof(BW));
            cout << "Blocked!!" << endl;
        }
    }
    pcap_close(handle);

    return 0;
}
