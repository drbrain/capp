require 'mkmf'

def require_header header
  have_header header or abort "missing #{header}"
end

require_header 'pcap/pcap.h'

require_header 'arpa/inet.h'
require_header 'net/ethernet.h'
require_header 'net/if_arp.h'
require_header 'netinet/ip.h'
require_header 'netinet/ip6.h'
require_header 'netinet/ip_icmp.h'
require_header 'netinet/udp.h'
require_header 'sys/socket.h'

have_header 'net/if_dl.h'

have_library 'pcap' or abort 'missing pcap library'

have_macro 'RETURN_ENUMERATOR' or abort 'missing C enumerator support'

have_macro 'PCAP_WARNING_TSTAMP_TYPE_NOTSUP'
have_macro 'PCAP_ERROR_PROMISC_PERM_DENIED'

create_header
create_makefile 'capp/capp'

