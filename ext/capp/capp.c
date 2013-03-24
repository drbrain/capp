#include <pcap/pcap.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <ruby.h>
#include <ruby/thread.h>
#include "extconf.h"

struct capp_packet {
    const struct pcap_pkthdr *header;
    const u_char *data;
};

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
    if (!RTEST(timeout))     timeout     = INT2NUM(1000);

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

    rb_ivar_set(obj, id_device, device);

    return obj;
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

static void *
capp_loop_callback_with_gvl(void *ptr)
{
    struct capp_packet *packet = (struct capp_packet *)ptr;

    rb_yield(capp_make_packet(packet->header, packet->data));

    return NULL;
}

static void
capp_loop_callback(u_char *args, const struct pcap_pkthdr *header,
	const u_char *data)
{
    struct capp_packet packet;

    packet.header = header;
    packet.data = data;

    rb_thread_call_with_gvl(capp_loop_callback_with_gvl, (void *)&packet);
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
    pcap_t *handle = (pcap_t *)ptr;
    int res;

    for (;;) {
	res = pcap_loop(handle, 0, capp_loop_callback, NULL);

	if (res != 0)
	    break;
    }

    return (void *)res;
}

static VALUE
capp_loop_run(VALUE self)
{
    pcap_t *handle;
    int res;

    GetCapp(self, handle);

    res = (int)rb_thread_call_without_gvl(capp_loop_run_no_gvl,
	    (void *)handle, capp_loop_interrupt, (void *)handle);

    if (res == -1)
	rb_raise(eCappError, "%s", pcap_geterr(handle));

    return self;
}

static VALUE
capp_loop(VALUE self)
{
    RETURN_ENUMERATOR(self, 0, 0);

    rb_ensure(capp_loop_run, self, capp_loop_end, self);

    return self;
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

    rb_define_singleton_method(cCapp, "default_device_name", capp_s_default_device_name, 0);
    rb_define_singleton_method(cCapp, "devices", capp_s_devices, 0);
    rb_define_singleton_method(cCapp, "live", capp_s_open_live, -1);

    rb_define_method(cCapp, "filter=", capp_set_filter, 1);
    rb_define_method(cCapp, "loop", capp_loop, 0);
    rb_define_method(cCapp, "promiscuous=", capp_set_promisc, 1);
    rb_define_method(cCapp, "snaplen=", capp_set_snaplen, 1);
    rb_define_method(cCapp, "stats", capp_stats, 0);
    rb_define_method(cCapp, "timeout=", capp_set_timeout, 1);
}

