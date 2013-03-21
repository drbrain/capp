require 'mkmf'

have_header 'pcap/pcap.h' or abort 'missing pcap/pcap.h'
have_library 'pcap'       or abort 'missing pcap library'

have_macro 'PCAP_WARNING_TSTAMP_TYPE_NOTSUP'
have_macro 'PCAP_ERROR_PROMISC_PERM_DENIED'

create_header
create_makefile 'pcap'

