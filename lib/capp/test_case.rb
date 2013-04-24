require 'minitest/autorun'
require 'capp'

class Capp::TestCase < MiniTest::Unit::TestCase

  ARP_DUMP        = File.expand_path '../../../test/arp.pcap',    __FILE__
  EAP_802_1X_DUMP = File.expand_path '../../../test/802.1X.pcap', __FILE__
  ICMP4_DUMP      = File.expand_path '../../../test/icmp4.pcap',  __FILE__
  ICMP6_DUMP      = File.expand_path '../../../test/icmp6.pcap',  __FILE__
  TCP4_DUMP       = File.expand_path '../../../test/tcp4.pcap',   __FILE__
  TCP6_DUMP       = File.expand_path '../../../test/tcp6.pcap',   __FILE__
  UDP4_DUMP       = File.expand_path '../../../test/udp4.pcap',   __FILE__
  UDP6_DUMP       = File.expand_path '../../../test/udp6.pcap',   __FILE__

  def packet dump
    Capp.offline(dump).loop.first
  end

end

