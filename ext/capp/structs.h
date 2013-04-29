/*
 * The following items are copied from tcpdump.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. The names of the authors may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

typedef u_int32_t tcp_seq;

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
    u_int16_t       th_sport;               /* source port */
    u_int16_t       th_dport;               /* destination port */
    tcp_seq         th_seq;                 /* sequence number */
    tcp_seq         th_ack;                 /* acknowledgement number */
    u_int8_t        th_offx2;               /* data offset, rsvd */
    u_int8_t        th_flags;
    u_int16_t       th_win;                 /* window */
    u_int16_t       th_sum;                 /* checksum */
    u_int16_t       th_urp;                 /* urgent pointer */
};

#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udphdr {
    u_int16_t       uh_sport;               /* source port */
    u_int16_t       uh_dport;               /* destination port */
    u_int16_t       uh_ulen;                /* udp length */
    u_int16_t       uh_sum;                 /* udp checksum */
};

/*
 * Byte-swap a 32-bit number.
 * ("htonl()" or "ntohl()" won't work - we want to byte-swap even on
 * big-endian platforms.)
 */
#define	SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))

