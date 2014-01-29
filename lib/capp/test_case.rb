require 'minitest/autorun'
require 'capp'

##
# Capp::TestCase contains some useful methods for testing parts of Capp.
#
# The _DUMP constants are created from pcap files in the test directory.  You
# can create your own capture from tcpdump:
#
#   tcpdump -r test/my.pcap [your specific capture arguments]

class Capp::TestCase < Minitest::Test

  ##
  # An ARP packet

  ARP_DUMP        = File.expand_path '../../../test/arp.pcap',    __FILE__

  ##
  # An EAP 802.1X packet

  EAP_802_1X_DUMP = File.expand_path '../../../test/802.1X.pcap', __FILE__

  ##
  # An ICMPv4 packet

  ICMP4_DUMP      = File.expand_path '../../../test/icmp4.pcap',  __FILE__

  ##
  # An ICMPv6 packet

  ICMP6_DUMP      = File.expand_path '../../../test/icmp6.pcap',  __FILE__

  ##
  # A TCPv4 packet

  TCP4_DUMP       = File.expand_path '../../../test/tcp4.pcap',   __FILE__

  ##
  # A TCPv6 packet

  TCP6_DUMP       = File.expand_path '../../../test/tcp6.pcap',   __FILE__

  ## A UDPv4 packet

  UDP4_DUMP       = File.expand_path '../../../test/udp4.pcap',   __FILE__

  ##
  # A UDPv6 packet

  UDP6_DUMP       = File.expand_path '../../../test/udp6.pcap',   __FILE__

  ##
  # Returns the first packet in +dump+

  def packet dump
    Capp.offline(dump).loop.first
  end

end

