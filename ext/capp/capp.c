#include <pcap/pcap.h>

#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <ruby.h>
#include <ruby/io.h>

#include "extconf.h"
#include "structs.h"

#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

/* Ethernet functions in the internet headers?  WTF Linux? */
#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h>
#endif

#ifdef HAVE_RUBY_THREAD_H
#include <ruby/thread.h>
#endif

#ifndef ETHERTYPE_PAE
#define ETHERTYPE_PAE 0x888e
#endif

#ifndef ETHERTYPE_RSN_PREAUTH
#define ETHERTYPE_RSN_PREAUTH 0x88c7
#endif

#ifndef ARPHRD_FRELAY
#define ARPHRD_FRELAY 15
#endif

#ifndef ARPHRD_IEEE1394_EUI64
#define ARPHRD_IEEE1394_EUI64 27
#endif

#ifndef ARPOP_REVREQUEST
#define ARPOP_REVREQUEST 3
#endif

#ifndef ARPOP_REVREPLY
#define ARPOP_REVREPLY 4
#endif

#ifndef ARPOP_INVREQUEST
#define ARPOP_INVREQUEST 8
#endif

#ifndef ARPOP_INVREPLY
#define ARPOP_INVREPLY 9
#endif

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xFFFFFFFF
#endif

#ifndef NUM2USHORT
#define NUM2USHORT (unsigned short)NUM2UINT
#endif

struct capp_loop_args {
    pcap_t *handle;
    int datalink;
    const struct pcap_pkthdr *header;
    const u_char *data;
};

#define GetCapp(obj, capp) Data_Get_Struct(obj, pcap_t, capp)

static ID id_arp;
static ID id_drop;
static ID id_ethernet;
static ID id_icmp;
static ID id_ifdrop;
static ID id_ipv4;
static ID id_ipv6;
static ID id_iv_datalink;
static ID id_iv_device;
static ID id_recv;
static ID id_type;
static ID id_tcp;
static ID id_udp;
static ID id_unknown_layer3;
static ID id_unpack_sockaddr_in;

static VALUE cCapp;
static VALUE cCappAddress;
static VALUE cCappDevice;
static VALUE cCappPacket;
static VALUE cCappPacketARPHeader;
static VALUE cCappPacketEthernetHeader;
static VALUE cCappPacketICMPHeader;
static VALUE cCappPacketIPv4Header;
static VALUE cCappPacketIPv6Header;
static VALUE cCappPacketTCPHeader;
static VALUE cCappPacketUDPHeader;
static VALUE cCappPacketUnknownLayer3Header;
static VALUE cSocket;

static VALUE eCappError;

/*
 * call-seq:
 *   Capp.default_device_name -> string
 *
 * Returns the default device name
 */
static VALUE
capp_s_default_device_name(VALUE klass)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;

    *errbuf = '\0';

    device = pcap_lookupdev(errbuf);

    if (device == NULL)
	rb_raise(eCappError, "pcap_create: %s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    return rb_usascii_str_new_cstr(device);
}

static VALUE
capp_sockaddr_to_address(struct sockaddr *addr)
{
    VALUE address, sockaddr_string;
#ifdef HAVE_NET_IF_DL_H
    struct ether_addr *ether;
    struct sockaddr_dl *dl;
#endif

    if (NULL == addr)
	return Qnil;

    switch (addr->sa_family) {
    case AF_INET:
	sockaddr_string = rb_str_new((char *)addr, sizeof(struct sockaddr_in));
	address =
	    rb_funcall(cSocket, id_unpack_sockaddr_in, 1, sockaddr_string);
	return rb_ary_entry(address, 1);
    case AF_INET6:
	sockaddr_string = rb_str_new((char *)addr, sizeof(struct sockaddr_in6));
	address =
	    rb_funcall(cSocket, id_unpack_sockaddr_in, 1, sockaddr_string);
	return rb_ary_entry(address, 1);
#ifdef HAVE_NET_IF_DL_H
    case AF_LINK:
	dl = (struct sockaddr_dl *)addr;
	ether = (struct ether_addr *)LLADDR(dl);

	return rb_usascii_str_new_cstr(ether_ntoa(ether));
#endif
    default:
	return rb_usascii_str_new_cstr("(unsupported address family)");
    }
}

static VALUE
capp_addr_to_addresses(pcap_addr_t *addrs)
{
    VALUE address, addresses, addr_args[4];
    pcap_addr_t *addr;

    addresses = rb_ary_new();

    if (addrs) {
	for (addr = addrs; addr; addr = addr->next) {
	    addr_args[0] = capp_sockaddr_to_address(addr->addr);
	    addr_args[1] = capp_sockaddr_to_address(addr->netmask);
	    addr_args[2] = capp_sockaddr_to_address(addr->broadaddr);
	    addr_args[3] = capp_sockaddr_to_address(addr->dstaddr);

	    address = rb_class_new_instance(4, addr_args, cCappAddress);

	    rb_ary_push(addresses, address);
	}
    }

    return addresses;
}

/*
 * call-seq:
 *   Capp.devices -> array
 *
 * Returns an Array containing the devices and their various addresses:
 *
 *   [#<struct Capp::Address
 *     address="lo0",
 *     netmask=nil,
 *     broadcast=
 *      [#<struct Capp::Address
 *        address="",
 *        netmask=nil,
 *        broadcast=nil,
 *        destination=nil>,
 *       #<struct Capp::Address
 *        address="fe80::1%lo0",
 *        netmask="ffff:ffff:ffff:ffff::",
 *        broadcast=nil,
 *        destination=nil>,
 *       #<struct Capp::Address
 *        address="127.0.0.1",
 *        netmask="255.0.0.0",
 *        broadcast=nil,
 *        destination=nil>,
 *       #<struct Capp::Address
 *        address="::1",
 *        netmask="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
 *        broadcast=nil,
 *        destination=nil>],
 *     destination=1>,
 *     # [...]
 *   ]
 */
static VALUE
capp_s_devices(VALUE klass)
{
    VALUE device, devices, dev_args[4];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *iface, *ifaces;

    *errbuf = '\0';

    if (pcap_findalldevs(&ifaces, errbuf))
	rb_raise(eCappError, "pcap_create: %s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    devices = rb_ary_new();

    for (iface = ifaces; iface; iface = iface->next) {
	dev_args[0] = rb_usascii_str_new_cstr(iface->name);
	if (iface->description) {
	    dev_args[1] = rb_usascii_str_new_cstr(iface->description);
	} else {
	    dev_args[1] = Qnil;
	}
	dev_args[2] = capp_addr_to_addresses(iface->addresses);
	dev_args[3] = UINT2NUM(iface->flags);

	device = rb_class_new_instance(4, dev_args, cCappAddress);

	rb_ary_push(devices, device);
    }

    pcap_freealldevs(ifaces);

    return devices;
}

/*
 * call-seq:
 *   Capp.live						    -> capp
 *   Capp.live device					    -> capp
 *   Capp.live device, capture_length,                      -> capp
 *   Capp.live device, capture_length, promiscuous          -> capp
 *   Capp.live device, capture_length, promiscuous, timeout -> capp
 *
 * Creates a new Capp.
 *
 * +device+ is the device to capture packets from.  If the device is omitted
 * the default device (::default_device_name) is used.
 *
 * +capture_length+ is the number of bytes to capture from each packet.  If
 * a length is omitted 65535 is used.
 *
 * +promiscuous+ places the device in promiscuous mode when true, allowing you
 * to see packets not sent to or from the device.  Promiscuous mode is enabled
 * by default.
 *
 * The +timeout+ is the number of maximum number of milliseconds that will
 * elapse between receiving a packet and yielding it to the block given to
 * #loop.  The default timeout is 10 milliseconds.  See #timeout= for further
 * discussion.
 */
static VALUE
capp_s_open_live(int argc, VALUE *argv, VALUE klass)
{
    VALUE obj, device, snaplen, promiscuous, timeout;
    int promisc = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    rb_scan_args(argc, argv, "04", &device, &snaplen, &promiscuous, &timeout);

    if (!RTEST(device))      device      = capp_s_default_device_name(klass);
    if (!RTEST(snaplen))     snaplen     = INT2NUM(-1);
    if (!RTEST(promiscuous)) promiscuous = Qtrue;
    if (!RTEST(timeout))     timeout     = INT2NUM(10);

    if (RTEST(promiscuous))
	promisc = 1;

    *errbuf = '\0';

    handle = pcap_open_live(StringValueCStr(device), NUM2INT(snaplen),
	    promisc, NUM2INT(timeout), errbuf);

    if (NULL == handle)
	rb_raise(eCappError, "pcap_create: %s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    obj = Data_Wrap_Struct(klass, NULL, pcap_close, handle);

    rb_ivar_set(obj, id_iv_device, device);

    return obj;
}

/*
 * call-seq:
 *   Capp.offline file     -> capp
 *   Capp.offline filename -> capp
 *
 * Creates an offline Capp that reads from a pcap savefile.  A savefile may be
 * loaded from an open +file+:
 *
 *   open 'savefile' do |io|
 *     capp = Capp.offline io
 *     # ...
 *   end
 *
 * Or a +filename+:
 *
 *   capp = Capp.offline 'savefile'
 */
static VALUE
capp_s_open_offline(VALUE klass, VALUE file)
{
    VALUE obj;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    *errbuf = '\0';

    if (TYPE(file) == T_FILE) {
	rb_io_t *fptr;

	GetOpenFile(file, fptr);

	handle = pcap_fopen_offline(rb_io_stdio_file(fptr), errbuf);
    } else {
	handle = pcap_open_offline(StringValueCStr(file), errbuf);
    }

    if (NULL == handle) {
	if (RFILE(file))
	    rb_raise(eCappError, "pcap_fopen_offline: %s", errbuf);

	rb_raise(eCappError, "pcap_open_offline: %s", errbuf);
    }

    if (*errbuf)
	rb_warn("%s", errbuf);

    obj = Data_Wrap_Struct(klass, NULL, pcap_close, handle);

    rb_ivar_set(obj, id_iv_device, Qnil);

    return obj;
}

static VALUE
capp_make_ether_str(const struct ether_addr *addr)
{
    return rb_usascii_str_new_cstr(ether_ntoa(addr));
}

static void
capp_make_unknown_layer3_header(VALUE headers, off_t offset)
{
    VALUE unknown_args[1];

    unknown_args[0] = UINT2NUM(offset);

    rb_hash_aset(headers, ID2SYM(id_unknown_layer3),
	    rb_class_new_instance(1, unknown_args, cCappPacketUnknownLayer3Header));
}

static void
capp_make_ethernet_header(VALUE headers, const struct ether_header *ether)
{
    VALUE ether_args[3];

    ether_args[0] =
	capp_make_ether_str((struct ether_addr *)ether->ether_dhost);
    ether_args[1] =
	capp_make_ether_str((struct ether_addr *)ether->ether_shost);
    ether_args[2] = UINT2NUM(ntohs(ether->ether_type));

    rb_hash_aset(headers, ID2SYM(id_ethernet),
	    rb_class_new_instance(3, ether_args, cCappPacketEthernetHeader));
}

static void
capp_make_icmp_header(VALUE headers, const struct icmp *header)
{
    VALUE icmp_args[3];

    icmp_args[0] = UINT2NUM(header->icmp_type);
    icmp_args[1] = UINT2NUM(header->icmp_code);
    icmp_args[2] = UINT2NUM(ntohs(header->icmp_cksum));

    rb_hash_aset(headers, ID2SYM(id_icmp),
	    rb_class_new_instance(3, icmp_args, cCappPacketICMPHeader));
}

static void
capp_make_tcp_header(VALUE headers, const struct tcphdr *header)
{
    VALUE tcp_args[9];

    tcp_args[0] = UINT2NUM(ntohs(header->th_sport));
    tcp_args[1] = UINT2NUM(ntohs(header->th_dport));
    tcp_args[2] = UINT2NUM(ntohl(header->th_seq));
    tcp_args[3] = UINT2NUM(ntohl(header->th_ack));
    tcp_args[4] = UINT2NUM(TH_OFF(header));
    tcp_args[5] = UINT2NUM(header->th_flags);
    tcp_args[6] = UINT2NUM(ntohs(header->th_win));
    tcp_args[7] = UINT2NUM(ntohs(header->th_sum));
    tcp_args[8] = UINT2NUM(ntohs(header->th_urp));

    rb_hash_aset(headers, ID2SYM(id_tcp),
	    rb_class_new_instance(9, tcp_args, cCappPacketTCPHeader));
}

static void
capp_make_udp_header(VALUE headers, const struct udphdr *header)
{
    VALUE udp_args[4];

    udp_args[0] = UINT2NUM(ntohs(header->uh_sport));
    udp_args[1] = UINT2NUM(ntohs(header->uh_dport));
    udp_args[2] = UINT2NUM(ntohs(header->uh_ulen));
    udp_args[3] = UINT2NUM(ntohs(header->uh_sum));

    rb_hash_aset(headers, ID2SYM(id_udp),
	    rb_class_new_instance(4, udp_args, cCappPacketUDPHeader));
}

static void
capp_make_arp_header(VALUE headers, const struct arphdr *header)
{
    VALUE arp_args[7];
    u_char hln, pln;
    u_short hrd, pro;
    u_short sha_offset, spa_offset, tha_offset, tpa_offset;

    hrd = ntohs(header->ar_hrd);
    arp_args[0] = UINT2NUM(hrd);

    pro = ntohs(header->ar_pro);
    arp_args[1] = UINT2NUM(pro);
    arp_args[2] = UINT2NUM(ntohs(header->ar_op));

    hln = header->ar_hln;
    pln = header->ar_pln;

    sha_offset = sizeof(struct arphdr);
    spa_offset = sizeof(struct arphdr) + hln;
    tha_offset = sizeof(struct arphdr) + hln + pln;
    tpa_offset = sizeof(struct arphdr) + hln + pln + hln;

    switch (hrd) {
    case ARPHRD_ETHER:
	arp_args[3] =
	    capp_make_ether_str((struct ether_addr *)((char *)header + sha_offset));
	arp_args[5] =
	    capp_make_ether_str((struct ether_addr *)((char *)header + tha_offset));
	break;
    default:
	rb_raise(rb_eNotImpError, "unsupported ARP hardware type %d", hrd);
    }

    switch (pro) {
    case ETHERTYPE_IP:
	arp_args[4] =
	    rb_usascii_str_new_cstr(inet_ntoa(*(struct in_addr *)((char *)header + spa_offset)));
	arp_args[6] =
	    rb_usascii_str_new_cstr(inet_ntoa(*(struct in_addr *)((char *)header + tpa_offset)));
	break;
    default:
	rb_raise(rb_eNotImpError, "unsupported ARP protocol %x", pro);
    }

    rb_hash_aset(headers, ID2SYM(id_arp),
	    rb_class_new_instance(7, arp_args, cCappPacketARPHeader));
}

static void
capp_make_ipv4_header(VALUE headers, const struct ip *header)
{
    const char * ip_payload;
    VALUE ipv4_args[11];

    ipv4_args[0]  = UINT2NUM(header->ip_v);
    ipv4_args[1]  = UINT2NUM(header->ip_hl);
    ipv4_args[2]  = UINT2NUM(header->ip_tos);
    ipv4_args[3]  = UINT2NUM(ntohs(header->ip_len));
    ipv4_args[4]  = UINT2NUM(ntohs(header->ip_id));
    ipv4_args[5]  = UINT2NUM(ntohs(header->ip_off));
    ipv4_args[6]  = UINT2NUM(header->ip_ttl);
    ipv4_args[7]  = UINT2NUM(header->ip_p);
    ipv4_args[8]  = UINT2NUM(ntohs(header->ip_sum));
    ipv4_args[9]  = rb_usascii_str_new_cstr(inet_ntoa(header->ip_src));
    ipv4_args[10] = rb_usascii_str_new_cstr(inet_ntoa(header->ip_dst));

    ip_payload = (char *)header + header->ip_hl * 4;

    switch (header->ip_p) {
    case IPPROTO_ICMP:
	capp_make_icmp_header(headers, (const struct icmp *)ip_payload);
	break;
    case IPPROTO_TCP:
	capp_make_tcp_header(headers, (const struct tcphdr *)ip_payload);
	break;
    case IPPROTO_UDP:
	capp_make_udp_header(headers, (const struct udphdr *)ip_payload);
	break;
    }

    rb_hash_aset(headers, ID2SYM(id_ipv4),
	    rb_class_new_instance(11, ipv4_args, cCappPacketIPv4Header));
}

static VALUE
capp_make_ipv6_addr(struct in6_addr addr)
{
    char buf[INET6_ADDRSTRLEN];
    const char *ptr;

    ptr = inet_ntop(AF_INET6, &addr, buf, sizeof(buf));

    if (!ptr)
	rb_sys_fail("inet_ntop");

    return rb_usascii_str_new_cstr(ptr);
}

static void
capp_make_ipv6_header(VALUE headers, const struct ip6_hdr *header)
{
    const char * ip_payload;
    VALUE ipv6_args[8];

    ipv6_args[0] = UINT2NUM(6);
    ipv6_args[1] = UINT2NUM((header->ip6_flow >> 20) & 0xff);
    ipv6_args[2] = UINT2NUM(ntohl(header->ip6_flow & 0xfffff));
    ipv6_args[3] = UINT2NUM(ntohs(header->ip6_plen));
    ipv6_args[4] = UINT2NUM(header->ip6_nxt);
    ipv6_args[5] = UINT2NUM(header->ip6_hlim);
    ipv6_args[6] = capp_make_ipv6_addr(header->ip6_src);
    ipv6_args[7] = capp_make_ipv6_addr(header->ip6_dst);

    ip_payload = (char *)header + sizeof(struct ip6_hdr);

    switch (header->ip6_nxt) {
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
	capp_make_icmp_header(headers, (const struct icmp *)ip_payload);
	break;
    case IPPROTO_TCP:
	capp_make_tcp_header(headers, (const struct tcphdr *)ip_payload);
	break;
    case IPPROTO_UDP:
	capp_make_udp_header(headers, (const struct udphdr *)ip_payload);
	break;
    }

    rb_hash_aset(headers, ID2SYM(id_ipv6),
	    rb_class_new_instance(8, ipv6_args, cCappPacketIPv6Header));
}

static void
capp_make_packet_ethernet(VALUE headers, const u_char *data)
{
    VALUE ether_header;
    uint16_t ethertype;
    size_t ether_header_size = sizeof(struct ether_header);

    capp_make_ethernet_header(headers, (const struct ether_header *)data);

    ether_header = rb_hash_aref(headers, ID2SYM(id_ethernet));
    ethertype = NUM2USHORT(rb_funcall(ether_header, id_type, 0));

    switch (ethertype) {
    case ETHERTYPE_ARP:
	capp_make_arp_header(headers,
		(const struct arphdr *)(data + ether_header_size));
	break;
    case ETHERTYPE_IP:
	capp_make_ipv4_header(headers,
		(const struct ip *)(data + ether_header_size));
	break;
    case ETHERTYPE_IPV6:
	capp_make_ipv6_header(headers,
		(const struct ip6_hdr *)(data + ether_header_size));
	break;
    default:
	capp_make_unknown_layer3_header(headers, ether_header_size);
	break;
    }
}

static void
capp_make_packet_null(VALUE headers, const u_char *data)
{
    uint32_t protocol_family;
    size_t protocol_family_size = sizeof(protocol_family);

    memcpy((char *)&protocol_family, (char *)data, protocol_family_size);

    /*
     * This isn't necessarily in our host byte order; if this is
     * a DLT_LOOP capture, it's in network byte order, and if
     * this is a DLT_NULL capture from a machine with the opposite
     * byte-order, it's in the opposite byte order from ours.
     *
     * If the upper 16 bits aren't all zero, assume it's byte-swapped.
     */
    if ((protocol_family & 0xFFFF0000) != 0)
	protocol_family = SWAPLONG(protocol_family);

    switch (protocol_family) {
    case PF_INET:
	capp_make_ipv4_header(headers,
		(const struct ip *)(data + protocol_family_size));
	break;
    case PF_INET6:
	capp_make_ipv6_header(headers,
		(const struct ip6_hdr *)(data + protocol_family_size));
	break;
    default:
	capp_make_unknown_layer3_header(headers, protocol_family_size);
	break;
    }
}

/*
 * capp_make_packet parses out the packet structure (if it understands it) and
 * calls Capp::Packet::new.
 *
 * Parsing starts at the datalink level and works its way through the packet
 * to the payload.  Each parsing function is passed the payload for the
 * current packet and the collected headers.  The function must insert new
 * data from the packet payload into the headers and repeat, with its payload,
 * if possible.
 */

static VALUE
capp_make_packet(int datalink, const struct pcap_pkthdr *header,
	const u_char *data)
{
    VALUE headers = rb_hash_new();
    VALUE packet_args[6];

    switch (datalink) {
    case DLT_NULL:
	capp_make_packet_null(headers, data);
	break;
    case DLT_EN10MB:
	capp_make_packet_ethernet(headers, data);
	break;
    default:
	rb_raise(rb_eNotImpError, "unknown datalink type %d", datalink);
	break; /* unreachable */
    }

    packet_args[0] = rb_time_new(header->ts.tv_sec, header->ts.tv_usec);
    packet_args[1] = UINT2NUM(header->len);
    packet_args[2] = UINT2NUM(header->caplen);
    packet_args[3] = rb_str_new((const char *)data, header->caplen);
    packet_args[4] = UINT2NUM(datalink);
    packet_args[5] = headers;

    return rb_class_new_instance(6, packet_args, cCappPacket);
}

static void *
capp_loop_callback_with_gvl(void *ptr)
{
    struct capp_loop_args *args = (struct capp_loop_args *)ptr;

    rb_yield(capp_make_packet(args->datalink, args->header, args->data));

    return NULL;
}

static void
capp_loop_callback(u_char *ptr, const struct pcap_pkthdr *header,
	const u_char *data)
{
    struct capp_loop_args *args = (struct capp_loop_args *)ptr;

    args->header = header;
    args->data   = data;

    rb_thread_call_with_gvl(capp_loop_callback_with_gvl, (void *)args);
}

static VALUE
capp_loop_end(VALUE self)
{
    pcap_t *handle;

    GetCapp(self, handle);

    pcap_breakloop(handle);

    return Qnil;
}

static void
capp_loop_interrupt(void *ptr)
{
    pcap_t *handle = (pcap_t *)ptr;

    pcap_breakloop(handle);
}

static void *
capp_loop_run_no_gvl(void *ptr)
{
    struct capp_loop_args *args = (struct capp_loop_args *)ptr;
    int res;

    res = pcap_loop(args->handle, -1, capp_loop_callback, (u_char *)ptr);

    return (void *)(intptr_t)res;
}

static VALUE
capp_loop_run(VALUE self)
{
    struct capp_loop_args args;
    int res;

    GetCapp(self, args.handle);

    args.datalink = pcap_datalink(args.handle);

    rb_ivar_set(self, id_iv_datalink, INT2NUM(args.datalink));

    res = (int)(intptr_t)rb_thread_call_without_gvl(capp_loop_run_no_gvl,
	    (void *)&args, capp_loop_interrupt, (void *)args.handle);

    if (res == -1)
	rb_raise(eCappError, "%s", pcap_geterr(args.handle));

    return self;
}

/*
 * call-seq:
 *   capp.loop { |packet| ... } -> self
 *   capp.loop                  -> enumerator
 *
 * Starts capturing packets.  Each packet captured is yielded to the block.
 * Packets are instances of Capp::Packet.
 *
 * If no block is given an enumerator is returned.
 */
static VALUE
capp_loop(VALUE self)
{
    RETURN_ENUMERATOR(self, 0, 0);

    rb_ensure(capp_loop_run, self, capp_loop_end, self);

    return self;
}

/*
 * call-seq:
 *   capp.filter = filter -> self
 *
 * Sets the packet filter to the given +filter+ string.  The format is the
 * same format as tcpdump(1).  You can see the syntax at pcap-filter(7).
 */
static VALUE
capp_set_filter(VALUE self, VALUE filter)
{
    VALUE device;
    pcap_t *handle;
    struct bpf_program program;
    bpf_u_int32 network, netmask = PCAP_NETMASK_UNKNOWN;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;

    device = rb_ivar_get(self, id_iv_device);

    if (RTEST(device)) {
	*errbuf = '\0';

	res =
	    pcap_lookupnet(StringValueCStr(device), &network, &netmask, errbuf);

	if (res == -1)
	    rb_raise(eCappError, "%s", errbuf);

	if (*errbuf)
	    rb_warn("%s", errbuf);
    }

    GetCapp(self, handle);

    res = pcap_compile(handle, &program, StringValueCStr(filter), 0, netmask);

    if (res)
	rb_raise(eCappError, "%s", pcap_geterr(handle));

    res = pcap_setfilter(handle, &program);

    pcap_freecode(&program);

    if (res)
	rb_raise(eCappError, "%s", pcap_geterr(handle));

    return self;
}

/*
 * call-seq:
 *   capp.promiscuous = boolean
 *
 * Enables or disables promiscuous mode.
 */
static VALUE
capp_set_promisc(VALUE self, VALUE promiscuous)
{
    pcap_t *handle;
    int promisc = RTEST(promiscuous);

    GetCapp(self, handle);

    if (pcap_set_promisc(handle, promisc))
	rb_raise(eCappError, "pcap already activated");

    return promiscuous;
}

/*
 * call-seq:
 *   capp.snaplen = length
 *
 * Sets the packet capture length to +length+.
 */
static VALUE
capp_set_snaplen(VALUE self, VALUE snaplen)
{
    pcap_t *handle;

    GetCapp(self, handle);

    if (pcap_set_snaplen(handle, NUM2INT(snaplen)))
	rb_raise(eCappError, "pcap already activated");

    return snaplen;
}

/*
 * call-seq:
 *   capp.timeout = milliseconds
 *
 * Sets the timeout to +milliseconds+
 *
 * The +timeout+ is the number of maximum number of milliseconds that will
 * elapse between receiving a packet and yielding it to the block given to
 * #loop.
 *
 * Reducing the timeout will increase responsiveness as pcap_loop(3) must
 * "check in" more frequently while increasing the timeout will reduce
 * responsiveness.
 *
 * Setting the timeout too low may increase GVL contention when many packets
 * are arriving at once as #loop will be waking up frequently to service
 * captured packets.
 */
static VALUE
capp_set_timeout(VALUE self, VALUE milliseconds)
{
    pcap_t *handle;

    GetCapp(self, handle);

    if (pcap_set_timeout(handle, NUM2INT(milliseconds)))
	rb_raise(eCappError, "pcap already activated");

    return milliseconds;
}

/*
 * call-seq:
 *   capp.stats -> hash
 *
 * Retrieves packet capture statistics:
 *
 *   p capp.stats #=> {:drop => 0, :ifdrop => 0, :recv => 123}
 */
static VALUE
capp_stats(VALUE self)
{
    VALUE stats;
    pcap_t *handle;
    struct pcap_stat ps;

    GetCapp(self, handle);

    if (pcap_stats(handle, &ps))
	rb_raise(eCappError, "%s", pcap_geterr(handle));

    stats = rb_hash_new();

    rb_hash_aset(stats, ID2SYM(id_drop),   UINT2NUM(ps.ps_drop));
    rb_hash_aset(stats, ID2SYM(id_ifdrop), UINT2NUM(ps.ps_ifdrop));
    rb_hash_aset(stats, ID2SYM(id_recv),   UINT2NUM(ps.ps_recv));

    return stats;
}

/*
 * call-seq:
 *   capp.stop -> capp
 *
 * Stops a running loop
 */
static VALUE
capp_stop(VALUE self)
{
    pcap_t *handle;

    GetCapp(self, handle);

    pcap_breakloop(handle);

    return self;
}

void
Init_capp(void) {
    id_arp                = rb_intern("arp");
    id_drop               = rb_intern("drop");
    id_ethernet           = rb_intern("ethernet");
    id_icmp               = rb_intern("icmp");
    id_ifdrop             = rb_intern("ifdrop");
    id_ipv4               = rb_intern("ipv4");
    id_ipv6               = rb_intern("ipv6");
    id_iv_datalink        = rb_intern("@datalink");
    id_iv_device          = rb_intern("@device");
    id_recv               = rb_intern("recv");
    id_tcp                = rb_intern("tcp");
    id_type               = rb_intern("type");
    id_udp                = rb_intern("udp");
    id_unknown_layer3     = rb_intern("unknown_layer3");
    id_unpack_sockaddr_in = rb_intern("unpack_sockaddr_in");

    cCapp        = rb_define_class("Capp", rb_cObject);

    cCappAddress = rb_const_get(cCapp, rb_intern("Address"));
    cCappDevice  = rb_const_get(cCapp, rb_intern("Device"));
    cCappPacket  = rb_const_get(cCapp, rb_intern("Packet"));
    eCappError   = rb_const_get(cCapp, rb_intern("Error"));

    cCappPacketARPHeader =
	rb_const_get(cCappPacket, rb_intern("ARPHeader"));
    cCappPacketEthernetHeader =
	rb_const_get(cCappPacket, rb_intern("EthernetHeader"));
    cCappPacketICMPHeader =
	rb_const_get(cCappPacket, rb_intern("ICMPHeader"));
    cCappPacketIPv4Header =
	rb_const_get(cCappPacket, rb_intern("IPv4Header"));
    cCappPacketIPv6Header =
	rb_const_get(cCappPacket, rb_intern("IPv6Header"));
    cCappPacketTCPHeader =
	rb_const_get(cCappPacket, rb_intern("TCPHeader"));
    cCappPacketUDPHeader =
	rb_const_get(cCappPacket, rb_intern("UDPHeader"));
    cCappPacketUnknownLayer3Header =
	rb_const_get(cCappPacket, rb_intern("UnknownLayer3Header"));

    cSocket = rb_const_get(rb_cObject, rb_intern("Socket"));

    rb_undef_alloc_func(cCapp);

    rb_define_singleton_method(cCapp, "default_device_name", capp_s_default_device_name, 0);
    rb_define_singleton_method(cCapp, "devices", capp_s_devices, 0);
    rb_define_singleton_method(cCapp, "live", capp_s_open_live, -1);
    rb_define_singleton_method(cCapp, "offline", capp_s_open_offline, 1);

    rb_define_method(cCapp, "filter=", capp_set_filter, 1);
    rb_define_method(cCapp, "loop", capp_loop, 0);
    rb_define_method(cCapp, "promiscuous=", capp_set_promisc, 1);
    rb_define_method(cCapp, "snaplen=", capp_set_snaplen, 1);
    rb_define_method(cCapp, "stats", capp_stats, 0);
    rb_define_method(cCapp, "stop", capp_stop, 0);
    rb_define_method(cCapp, "timeout=", capp_set_timeout, 1);

    /* Document-const: ARPHRD_ETHER
     *
     * Ethernet hardware
     */
    rb_define_const(cCapp, "ARPHRD_ETHER", INT2NUM(ARPHRD_ETHER));

    /* Document-const: ARPHRD_FRELAY
     *
     * frame relay hardware
     */
    rb_define_const(cCapp, "ARPHRD_FRELAY", INT2NUM(ARPHRD_FRELAY));

    /* Document-const: ARPHRD_IEEE1394
     *
     * IEEE1394 (FireWire™) hardware
     */
    rb_define_const(cCapp, "ARPHRD_IEEE1394", INT2NUM(ARPHRD_IEEE1394));

    /* Document-const: ARPHRD_IEEE1394_EUI64
     *
     * IEEE1394 (FireWire™) hardware with EUI-64 addresses
     */
    rb_define_const(cCapp, "ARPHRD_IEEE1394_EUI64",
	    INT2NUM(ARPHRD_IEEE1394_EUI64));

    /* Document-const: ARPHRD_IEEE802
     *
     * token-ring hardware
     */
    rb_define_const(cCapp, "ARPHRD_IEEE802", INT2NUM(ARPHRD_IEEE802));

    /* Document-const: ARPOP_INVREPLY
     *
     * ARP response identifying peer
     */
    rb_define_const(cCapp, "ARPOP_INVREPLY", INT2NUM(ARPOP_INVREPLY));

    /* Document-const: ARPOP_INVREQUEST
     *
     * ARP request to identify peer
     */
    rb_define_const(cCapp, "ARPOP_INVREQUEST", INT2NUM(ARPOP_INVREQUEST));

    /* Document-const: ARPOP_REPLY
     *
     * ARP response to resolve request
     */
    rb_define_const(cCapp, "ARPOP_REPLY", INT2NUM(ARPOP_REPLY));

    /* Document-const: ARPOP_REQUEST
     *
     * ARP resolve address request
     */
    rb_define_const(cCapp, "ARPOP_REQUEST", INT2NUM(ARPOP_REQUEST));

    /* Document-const: ARPOP_REVREPLY
     *
     * ARP response giving protocol address
     */
    rb_define_const(cCapp, "ARPOP_REVREPLY", INT2NUM(ARPOP_REVREPLY));

    /* Document-const: ARPOP_REVREQUEST
     *
     * ARP request protocol address given hardware address
     */
    rb_define_const(cCapp, "ARPOP_REVREQUEST", INT2NUM(ARPOP_REVREQUEST));

    /* Document-const: DLT_NULL
     *
     * BSD loopback encapsulation.
     */
    rb_define_const(cCapp, "DLT_NULL", INT2NUM(DLT_NULL));

    /* Document-const: DLT_EN10MB
     *
     * Ethernet encapsulation.
     */
    rb_define_const(cCapp, "DLT_EN10MB", INT2NUM(DLT_EN10MB));

    /* Document-const: ETHERTYPE_ARP
     *
     * Address Resolution Protocol
     */
    rb_define_const(cCapp, "ETHERTYPE_ARP", INT2NUM(ETHERTYPE_ARP));

    /* Document-const: ETHERTYPE_IP
     *
     * IPv4
     */
    rb_define_const(cCapp, "ETHERTYPE_IP", INT2NUM(ETHERTYPE_IP));

    /* Document-const: ETHERTYPE_IPV6
     *
     * IPv6
     */
    rb_define_const(cCapp, "ETHERTYPE_IPV6", INT2NUM(ETHERTYPE_IPV6));

    /* Document-const: ETHERTYPE_LOOPBACK
     *
     * Used to test interfaces
     */
    rb_define_const(cCapp, "ETHERTYPE_LOOPBACK", INT2NUM(ETHERTYPE_LOOPBACK));

    /* Document-const: ETHERTYPE_PUP
     *
     * PUP protocol
     */
    rb_define_const(cCapp, "ETHERTYPE_PUP", INT2NUM(ETHERTYPE_PUP));

    /* Document-const: ETHERTYPE_PAE
     *
     * EAPOL PAE/802.1x
     */
    rb_define_const(cCapp, "ETHERTYPE_PAE", INT2NUM(ETHERTYPE_PAE));

    /* Document-const: ETHERTYPE_REVARP
     *
     * Reverse Address Resolution Protocol
     */
    rb_define_const(cCapp, "ETHERTYPE_REVARP", INT2NUM(ETHERTYPE_REVARP));

    /* Document-const: ETHERTYPE_RSN_PREAUTH
     *
     * 802.11i / RSN Pre-Authentication
     */
    rb_define_const(cCapp, "ETHERTYPE_RSN_PREAUTH",
	    INT2NUM(ETHERTYPE_RSN_PREAUTH));

    /* Document-const: ETHERTYPE_VLAN
     *
     * IEEE 802.1Q VLAN tagging
     */
    rb_define_const(cCapp, "ETHERTYPE_VLAN", INT2NUM(ETHERTYPE_VLAN));

    /* Document-const: TCP_ACK
     *
     * TCP Acknowledged flag
     */
    rb_define_const(cCapp, "TCP_ACK", INT2NUM(TH_ACK));

    /* Document-const: TCP_CWR
     *
     * TCP Congestion Window Reduced flag
     */
    rb_define_const(cCapp, "TCP_CWR", INT2NUM(TH_CWR));

    /* Document-const: TCP_ECE
     *
     * TCP ECN echo flag
     */
    rb_define_const(cCapp, "TCP_ECE", INT2NUM(TH_ECE));

    /* Document-const: TCP_FIN
     *
     * TCP Finish flag
     */
    rb_define_const(cCapp, "TCP_FIN", INT2NUM(TH_FIN));

    /* Document-const: TCP_PUSH
     *
     * TCP Push flag
     */
    rb_define_const(cCapp, "TCP_PUSH", INT2NUM(TH_PUSH));

    /* Document-const: TCP_RST
     *
     * TCP Reset flag
     */
    rb_define_const(cCapp, "TCP_RST", INT2NUM(TH_RST));

    /* Document-const: TCP_SYN
     *
     * TCP Synchronize flag
     */
    rb_define_const(cCapp, "TCP_SYN", INT2NUM(TH_SYN));

    /* Document-const: TCP_URG
     *
     * TCP Urgent flag
     */
    rb_define_const(cCapp, "TCP_URG", INT2NUM(TH_URG));
}

