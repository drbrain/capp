#include <pcap/pcap.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <ruby.h>
#include "extconf.h"

#define GetPcap(obj, pcap) Data_Get_Struct(obj, pcap_t, pcap)
#define GetFilter(obj, pcap) Data_Get_Struct(obj, struct bpf_program, pcap)

static ID id_drop, id_ifdrop, id_recv, id_unpack_sockaddr_in;

static VALUE cPcap;
static VALUE cPcapAddress;
static VALUE cPcapDevice;
static VALUE cPcapFilter;
static VALUE cPcapPacket;
static VALUE cSocket;

static VALUE ePcapError;

static VALUE
rb_pcap_s_create(VALUE klass, VALUE device)
{
    VALUE obj;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_create(StringValueCStr(device), errbuf);

    *errbuf = '\0';

    if (NULL == handle)
	rb_raise(ePcapError, "pcap_create: %s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    obj = Data_Wrap_Struct(klass, NULL, pcap_close, handle);

    return obj;
}

static VALUE
rb_pcap_sockaddr_to_address(struct sockaddr *addr)
{
    VALUE address, sockaddr_string;
    struct sockaddr_dl *dl;

    if (NULL == addr)
	return Qnil;

    sockaddr_string = rb_str_new((char *)addr, addr->sa_len);

    switch (addr->sa_family) {
    case AF_INET:
    case AF_INET6:
	address =
	    rb_funcall(cSocket, id_unpack_sockaddr_in, 1, sockaddr_string);
	return rb_ary_entry(address, 1);
    case AF_LINK:
	dl = (struct sockaddr_dl *)addr;

	return rb_str_new(LLADDR(dl), dl->sdl_alen);
    }

    return sockaddr_string;
}

static VALUE
rb_pcap_addr_to_addresses(pcap_addr_t *addrs)
{
    VALUE address, addresses, addr_args[4];

    addresses = rb_ary_new();

    if (addrs) {
	for (pcap_addr_t *addr = addrs; addr; addr = addr->next) {
	    addr_args[0] = rb_pcap_sockaddr_to_address(addr->addr);
	    addr_args[1] = rb_pcap_sockaddr_to_address(addr->netmask);
	    addr_args[2] = rb_pcap_sockaddr_to_address(addr->broadaddr);
	    addr_args[3] = rb_pcap_sockaddr_to_address(addr->dstaddr);

	    address = rb_class_new_instance(4, addr_args, cPcapAddress);

	    rb_ary_push(addresses, address);
	}
    }

    return addresses;
}

static VALUE
rb_pcap_s_devices(VALUE klass)
{
    VALUE device, devices, dev_args[4];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *ifaces;

    *errbuf = '\0';

    if (pcap_findalldevs(&ifaces, errbuf))
	rb_raise(ePcapError, "pcap_create: %s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    devices = rb_ary_new();

    for (pcap_if_t *iface = ifaces; iface; iface = iface->next) {
	dev_args[0] = rb_str_new_cstr(iface->name);
	if (iface->description) {
	    dev_args[1] = rb_str_new_cstr(iface->description);
	} else {
	    dev_args[1] = Qnil;
	}
	dev_args[2] = rb_pcap_addr_to_addresses(iface->addresses);
	if (iface->flags & PCAP_IF_LOOPBACK) {
	    dev_args[3] = Qtrue;
	} else {
	    dev_args[3] = Qfalse;
	}

	device = rb_class_new_instance(4, dev_args, cPcapAddress);

	rb_ary_push(devices, device);
    }

    pcap_freealldevs(ifaces);

    return devices;
}

static VALUE
rb_pcap_s_open_live(VALUE klass, VALUE device, VALUE snaplen,
	VALUE promiscuous, VALUE timeout)
{
    VALUE obj;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(StringValueCStr(device), NUM2INT(snaplen),
	    NUM2INT(promiscuous), NUM2INT(timeout), errbuf);

    *errbuf = '\0';

    if (NULL == handle)
	rb_raise(ePcapError, "pcap_create: %s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    obj = Data_Wrap_Struct(klass, NULL, pcap_close, handle);

    return obj;
}

static VALUE
rb_pcap_activate(VALUE self, VALUE snaplen)
{
    pcap_t *handle;
    int res;

    GetPcap(self, handle);

    res = pcap_activate(handle);

    switch (res) {
      case 0:
	break;
#ifdef HAVE_PCAP_WARNING_TSTAMP_TYPE_NOTSUP
      case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
	rb_warn("timestamp type not supported");
	break;
#endif
      case PCAP_WARNING_PROMISC_NOTSUP:
      case PCAP_WARNING:
	rb_warn("%s", pcap_geterr(handle));
	break;

#ifdef HAVE_PCAP_ERROR_PROMISC_PERM_DENIED
      case PCAP_ERROR_PROMISC_PERM_DENIED:
	rb_raise(ePcapError, "promiscuous permission denied");
#endif
      case PCAP_ERROR_ACTIVATED:
	rb_raise(ePcapError, "pcap already activated");
      case PCAP_ERROR_RFMON_NOTSUP:
	rb_raise(ePcapError, "RF monitoring not supported");
      case PCAP_ERROR_IFACE_NOT_UP:
	rb_raise(ePcapError, "interface not up");
      case PCAP_ERROR_PERM_DENIED:
      case PCAP_ERROR_NO_SUCH_DEVICE:
      case PCAP_ERROR:
	rb_raise(ePcapError, "%s", pcap_geterr(handle));
    }

    return snaplen;
}

static void
rb_pcap_loop_callback(u_char *args, const struct pcap_pkthdr *header,
	const u_char *packet) {
    VALUE self = (VALUE)args;

    rb_p(self);
    printf("woo\n");
}

static VALUE
rb_pcap_loop(VALUE self, VALUE count)
{
    pcap_t *handle;
    int res;

    GetPcap(self, handle);

    res = pcap_loop(handle, NUM2INT(count), rb_pcap_loop_callback,
	    (u_char *)self);

    if (res == -1) {
	rb_raise(ePcapError, "%s", pcap_geterr(handle));
    }

    return INT2NUM(res);
}

static VALUE
rb_pcap_next(VALUE self)
{
    VALUE packet, args[4];
    pcap_t *handle;
    struct pcap_pkthdr *header = NULL;
    const u_char *data = NULL;
    int res;

    GetPcap(self, handle);

    res = pcap_next_ex(handle, &header, &data);

    if (res == -1)
	rb_raise(ePcapError, "%s", pcap_geterr(handle));

    args[0] = rb_time_new(header->ts.tv_sec, header->ts.tv_usec);
    args[1] = UINT2NUM(header->len);
    args[2] = UINT2NUM(header->caplen);
    args[3] = rb_str_new((const char *)data, header->caplen);

    packet = rb_class_new_instance(4, args, cPcapPacket);

    return packet;
}

static VALUE
rb_pcap_set_filter(VALUE self, VALUE filter)
{
    pcap_t *handle;
    struct bpf_program *program;

    GetPcap(self, handle);
    GetFilter(filter, program);

    if (pcap_setfilter(handle, program))
	rb_raise(ePcapError, "%s", pcap_geterr(handle));

    return filter;
}

static VALUE
rb_pcap_set_promisc(VALUE self, VALUE promiscuous)
{
    pcap_t *handle;
    int promisc = RTEST(promiscuous);

    GetPcap(self, handle);

    if (pcap_set_promisc(handle, promisc))
	rb_raise(ePcapError, "pcap already activated");

    return promiscuous;
}

static VALUE
rb_pcap_set_snaplen(VALUE self, VALUE snaplen)
{
    pcap_t *handle;

    GetPcap(self, handle);

    if (pcap_set_snaplen(handle, NUM2INT(snaplen)))
	rb_raise(ePcapError, "pcap already activated");

    return snaplen;
}

static VALUE
rb_pcap_set_timeout(VALUE self, VALUE milliseconds)
{
    pcap_t *handle;

    GetPcap(self, handle);

    if (pcap_set_timeout(handle, NUM2INT(milliseconds)))
	rb_raise(ePcapError, "pcap already activated");

    return milliseconds;
}

static VALUE
rb_pcap_stats(VALUE self)
{
    VALUE stats;
    pcap_t *handle;
    struct pcap_stat ps;

    GetPcap(self, handle);

    if (pcap_stats(handle, &ps))
	rb_raise(ePcapError, "pcap already activated");

    stats = rb_hash_new();

    rb_hash_aset(stats, ID2SYM(id_drop),   UINT2NUM(ps.ps_drop));
    rb_hash_aset(stats, ID2SYM(id_ifdrop), UINT2NUM(ps.ps_ifdrop));
    rb_hash_aset(stats, ID2SYM(id_recv),   UINT2NUM(ps.ps_recv));

    return stats;
}

static void
rb_pcap_filter_free(struct bpf_program *program) {
    pcap_freecode(program);
    free(program);
}

static VALUE
rb_pcap_filter_s_create(VALUE klass, VALUE pcap, VALUE device, VALUE filter)
{
    VALUE obj;
    pcap_t *handle;
    struct bpf_program *program = ALLOC(struct bpf_program);
    bpf_u_int32 network, netmask;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;

    *errbuf = '\0';

    res = pcap_lookupnet(StringValueCStr(device), &network, &netmask, errbuf);

    if (res == -1)
	rb_raise(ePcapError, "%s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    GetPcap(pcap, handle);

    res = pcap_compile(handle, program, StringValueCStr(filter), 1, network);

    if (res) {
	free(program);
	rb_raise(ePcapError, "%s", pcap_geterr(handle));
    }

    obj = Data_Wrap_Struct(klass, NULL, rb_pcap_filter_free, program);

    return obj;
}

void
Init_pcap(void) {
    id_drop   = rb_intern("drop");
    id_ifdrop = rb_intern("ifdrop");
    id_recv   = rb_intern("recv");
    id_unpack_sockaddr_in = rb_intern("unpack_sockaddr_in");

    cPcap        = rb_const_get(rb_cObject, rb_intern("Pcap"));
    cPcapAddress = rb_const_get(cPcap, rb_intern("Address"));
    cPcapDevice  = rb_const_get(cPcap, rb_intern("Device"));
    cPcapPacket  = rb_const_get(cPcap, rb_intern("Packet"));
    ePcapError   = rb_const_get(cPcap, rb_intern("Error"));

    cSocket = rb_const_get(rb_cObject, rb_intern("Socket"));

    rb_undef_alloc_func(cPcap);

    rb_define_singleton_method(cPcap, "create", rb_pcap_s_create, 1);
    rb_define_singleton_method(cPcap, "devices", rb_pcap_s_devices, 0);
    rb_define_singleton_method(cPcap, "open_live", rb_pcap_s_open_live, 4);

    rb_define_method(cPcap, "activate", rb_pcap_activate, 0);
    rb_define_method(cPcap, "filter=", rb_pcap_set_filter, 1);
    rb_define_method(cPcap, "loop", rb_pcap_loop, 1);
    rb_define_method(cPcap, "next", rb_pcap_next, 0);
    rb_define_method(cPcap, "promiscuous=", rb_pcap_set_promisc, 1);
    rb_define_method(cPcap, "snaplen=", rb_pcap_set_snaplen, 1);
    rb_define_method(cPcap, "stats", rb_pcap_stats, 0);
    rb_define_method(cPcap, "timeout=", rb_pcap_set_timeout, 1);

    cPcapFilter = rb_define_class_under(cPcap, "Filter", rb_cObject);

    rb_undef_alloc_func(cPcap);

    rb_define_singleton_method(cPcapFilter, "compile",
	    rb_pcap_filter_s_create, 3);
}

