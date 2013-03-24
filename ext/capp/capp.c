#include <pcap/pcap.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <ruby.h>
#include "extconf.h"

#define GetCapp(obj, capp) Data_Get_Struct(obj, pcap_t, capp)

static ID id_device;
static ID id_drop;
static ID id_ifdrop;
static ID id_recv;
static ID id_unpack_sockaddr_in;

static VALUE cCapp;
static VALUE cCappAddress;
static VALUE cCappDevice;
static VALUE cCappPacket;
static VALUE cSocket;

static VALUE eCappError;

static VALUE
capp_s_create(VALUE klass, VALUE device)
{
    VALUE obj;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_create(StringValueCStr(device), errbuf);

    *errbuf = '\0';

    if (NULL == handle)
	rb_raise(eCappError, "pcap_create: %s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    obj = Data_Wrap_Struct(klass, NULL, pcap_close, handle);

    rb_ivar_set(obj, id_device, device);

    return obj;
}

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
capp_addr_to_addresses(pcap_addr_t *addrs)
{
    VALUE address, addresses, addr_args[4];

    addresses = rb_ary_new();

    if (addrs) {
	for (pcap_addr_t *addr = addrs; addr; addr = addr->next) {
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

static VALUE
capp_s_devices(VALUE klass)
{
    VALUE device, devices, dev_args[4];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *ifaces;

    *errbuf = '\0';

    if (pcap_findalldevs(&ifaces, errbuf))
	rb_raise(eCappError, "pcap_create: %s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    devices = rb_ary_new();

    for (pcap_if_t *iface = ifaces; iface; iface = iface->next) {
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

static VALUE
capp_s_open_live(VALUE klass, VALUE device, VALUE snaplen,
	VALUE promiscuous, VALUE timeout)
{
    VALUE obj;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(StringValueCStr(device), NUM2INT(snaplen),
	    NUM2INT(promiscuous), NUM2INT(timeout), errbuf);

    *errbuf = '\0';

    if (NULL == handle)
	rb_raise(eCappError, "pcap_create: %s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    obj = Data_Wrap_Struct(klass, NULL, pcap_close, handle);

    rb_ivar_set(obj, id_device, device);

    return obj;
}

static VALUE
capp_activate(VALUE self, VALUE snaplen)
{
    pcap_t *handle;
    int res;

    GetCapp(self, handle);

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
	rb_raise(eCappError, "promiscuous permission denied");
#endif
      case PCAP_ERROR_ACTIVATED:
	rb_raise(eCappError, "pcap already activated");
      case PCAP_ERROR_RFMON_NOTSUP:
	rb_raise(eCappError, "RF monitoring not supported");
      case PCAP_ERROR_IFACE_NOT_UP:
	rb_raise(eCappError, "interface not up");
      case PCAP_ERROR_PERM_DENIED:
      case PCAP_ERROR_NO_SUCH_DEVICE:
      case PCAP_ERROR:
	rb_raise(eCappError, "%s", pcap_geterr(handle));
    }

    return snaplen;
}

static VALUE
capp_get_nonblock(VALUE self)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int res;

    GetCapp(self, handle);

    *errbuf = '\0';

    res = pcap_getnonblock(handle, errbuf);

    if (-1 == res)
	rb_raise(eCappError, "pcap_create: %s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    if (res)
	return Qtrue;

    return Qfalse;
}

static VALUE
capp_make_packet(const struct pcap_pkthdr *header, const u_char *data)
{
    VALUE args[4];

    args[0] = rb_time_new(header->ts.tv_sec, header->ts.tv_usec);
    args[1] = UINT2NUM(header->len);
    args[2] = UINT2NUM(header->caplen);
    args[3] = rb_str_new((const char *)data, header->caplen);

    return rb_class_new_instance(4, args, cCappPacket);
}

static void
capp_loop_callback(u_char *args, const struct pcap_pkthdr *header,
	const u_char *data)
{
    rb_yield(capp_make_packet(header, data));
}

static VALUE
capp_loop_end(VALUE self)
{
    pcap_t *handle;

    GetCapp(self, handle);

    pcap_breakloop(handle);

    return Qnil;
}

static VALUE
capp_loop_run(VALUE self)
{
    pcap_t *handle;
    int res;

    GetCapp(self, handle);

    for (;;) {
	res = pcap_loop(handle, 0, capp_loop_callback, (u_char *)self);

	if (res == -1)
	    rb_raise(eCappError, "%s", pcap_geterr(handle));
    }

    return self;
}

static VALUE
capp_loop(VALUE self)
{

    rb_ensure(capp_loop_run, self, capp_loop_end, self);

    return self;
}

static VALUE
capp_next(VALUE self)
{
    pcap_t *handle;
    struct pcap_pkthdr *header = NULL;
    const u_char *data = NULL;
    int res;

    GetCapp(self, handle);

    res = pcap_next_ex(handle, &header, &data);

    switch (res) {
    case -2: /* out of packets in file */
	rb_raise(eCappError, "out of packets");
    case -1: /* error */
	rb_raise(eCappError, "%s", pcap_geterr(handle));
	break; /* not reached */
    case  0: /* timeout expired */
	return Qnil;
    case  1: /* read packet */
    default:
	break;
    }

    return capp_make_packet(header, data);
}

static VALUE
capp_set_filter(VALUE self, VALUE filter)
{
    VALUE device;
    pcap_t *handle;
    struct bpf_program program;
    bpf_u_int32 network, netmask;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;

    device = rb_ivar_get(self, id_device);

    *errbuf = '\0';

    res = pcap_lookupnet(StringValueCStr(device), &network, &netmask, errbuf);

    if (res == -1)
	rb_raise(eCappError, "%s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    GetCapp(self, handle);

    res = pcap_compile(handle, &program, StringValueCStr(filter), 0, netmask);

    if (res)
	rb_raise(eCappError, "%s", pcap_geterr(handle));

    if (pcap_setfilter(handle, &program))
	rb_raise(eCappError, "%s", pcap_geterr(handle));

    return self;
}

static VALUE
capp_set_nonblock(VALUE self, VALUE nonblock)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int res, value = 0;

    if (RTEST(nonblock))
	value = 1;

    GetCapp(self, handle);

    *errbuf = '\0';

    res = pcap_setnonblock(handle, value, errbuf);

    if (-1 == res)
	rb_raise(eCappError, "pcap_create: %s", errbuf);

    if (*errbuf)
	rb_warn("%s", errbuf);

    return nonblock;
}

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

static VALUE
capp_set_snaplen(VALUE self, VALUE snaplen)
{
    pcap_t *handle;

    GetCapp(self, handle);

    if (pcap_set_snaplen(handle, NUM2INT(snaplen)))
	rb_raise(eCappError, "pcap already activated");

    return snaplen;
}

static VALUE
capp_set_timeout(VALUE self, VALUE milliseconds)
{
    pcap_t *handle;

    GetCapp(self, handle);

    if (pcap_set_timeout(handle, NUM2INT(milliseconds)))
	rb_raise(eCappError, "pcap already activated");

    return milliseconds;
}

static VALUE
capp_stats(VALUE self)
{
    VALUE stats;
    pcap_t *handle;
    struct pcap_stat ps;

    GetCapp(self, handle);

    if (pcap_stats(handle, &ps))
	rb_raise(eCappError, "pcap already activated");

    stats = rb_hash_new();

    rb_hash_aset(stats, ID2SYM(id_drop),   UINT2NUM(ps.ps_drop));
    rb_hash_aset(stats, ID2SYM(id_ifdrop), UINT2NUM(ps.ps_ifdrop));
    rb_hash_aset(stats, ID2SYM(id_recv),   UINT2NUM(ps.ps_recv));

    return stats;
}

void
Init_capp(void) {
    id_device = rb_intern("device");
    id_drop   = rb_intern("drop");
    id_ifdrop = rb_intern("ifdrop");
    id_recv   = rb_intern("recv");
    id_unpack_sockaddr_in = rb_intern("unpack_sockaddr_in");

    cCapp        = rb_const_get(rb_cObject, rb_intern("Capp"));
    cCappAddress = rb_const_get(cCapp, rb_intern("Address"));
    cCappDevice  = rb_const_get(cCapp, rb_intern("Device"));
    cCappPacket  = rb_const_get(cCapp, rb_intern("Packet"));
    eCappError   = rb_const_get(cCapp, rb_intern("Error"));

    cSocket = rb_const_get(rb_cObject, rb_intern("Socket"));

    rb_undef_alloc_func(cCapp);

    rb_define_singleton_method(cCapp, "create", capp_s_create, 1);
    rb_define_singleton_method(cCapp, "default_device_name", capp_s_default_device_name, 0);
    rb_define_singleton_method(cCapp, "devices", capp_s_devices, 0);
    rb_define_singleton_method(cCapp, "open_live", capp_s_open_live, 4);

    rb_define_method(cCapp, "activate", capp_activate, 0);
    rb_define_method(cCapp, "filter=", capp_set_filter, 1);
    rb_define_method(cCapp, "loop", capp_loop, 0);
    rb_define_method(cCapp, "next", capp_next, 0);
    rb_define_method(cCapp, "nonblock", capp_get_nonblock, 0);
    rb_define_method(cCapp, "nonblock=", capp_set_nonblock, 1);
    rb_define_method(cCapp, "promiscuous=", capp_set_promisc, 1);
    rb_define_method(cCapp, "snaplen=", capp_set_snaplen, 1);
    rb_define_method(cCapp, "stats", capp_stats, 0);
    rb_define_method(cCapp, "timeout=", capp_set_timeout, 1);
}

