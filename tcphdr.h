#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr final {
    uint16_t th_sport;	/* source port */
	uint16_t th_dport;	/* destination port */
	uint32_t th_seq;		/* sequence number */
	uint32_t th_ack;		/* acknowledgement number */
	uint8_t th_x2:4;	/* (unused) */
	uint8_t th_off:4;	/* data offset */
	uint8_t th_flags;
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH    0x08
# define TH_ACK	0x10
# define TH_URG	0x20
	uint16_t th_win;	/* window */
	uint16_t th_sum;	/* checksum */
	uint16_t th_urp;	/* urgent pointer */


};
#pragma pack(pop)

#pragma pack(push, 1)
struct Pseudoheader{
    uint32_t sip;
    uint32_t dip;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t tcp_len;
}pseudoForward, pseudoBackward;
#pragma pack(pop)