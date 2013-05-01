require 'capp/test_case'

class TestCapp < Capp::TestCase

  def test_class_drop_privileges_not_root
    dir  = Dir.pwd
    orig = Etc.getpwuid

    skip 'you are root' if Process.uid.zero? and Process.euid.zero?

    Capp.drop_privileges 'nobody'

    user = Etc.getpwuid

    assert_equal orig.uid, user.uid 
    assert_equal orig.gid, user.gid 

    assert_equal dir, Dir.pwd
  end

  def test_class_offline_file
    open ICMP4_DUMP do |io|
      capp = Capp.offline io

      assert capp.loop.first
    end
  end

  def test_class_offline_filename
    capp = Capp.offline ICMP4_DUMP

    assert capp.loop.first
  end

  def test_class_open_file
    open ICMP4_DUMP do |io|
      capp = Capp.open io

      assert capp.loop.first
    end
  end

  def test_class_open_filename
    capp = Capp.open ICMP4_DUMP

    assert capp.loop.first
  end

  def test_class_pcap_lib_version
    lib_version = Capp.pcap_lib_version

    assert_match 'libpcap', lib_version
    assert_match %r%\d\.%,  lib_version
  end

  def test_ethernet_header
    capp = Capp.offline UDP4_DUMP

    packet = capp.loop.first

    header = packet.ethernet_header

    assert_equal 'ff:ff:ff:ff:ff:ff', header.destination
    assert_equal '20:c9:d0:48:eb:73', header.source
    assert_equal Capp::ETHERTYPE_IP,  header.type
  end

  def test_filter_equals
    capp = Capp.offline ICMP4_DUMP

    capp.filter = 'icmp[icmptype] = icmp-echo'

    assert_equal 2, capp.loop.count
  end

  def test_filter_equals_garbage
    capp = Capp.offline ICMP4_DUMP

    assert_raises Capp::Error do
      capp.filter = 'garbage'
    end
  end

  def test_arp_header
    capp = Capp.offline ARP_DUMP

    packet = capp.loop.first

    header = packet.arp_header

    assert_equal Capp::ARPHRD_ETHER,            header.hardware
    assert_equal Capp::ETHERTYPE_IP,            header.protocol
    assert_equal Capp::ARPOP_REQUEST,           header.operation
    assert_match %r%\A0?2:c0:de:0?1:0?1:0?1\z%, header.sender_hardware_address
    assert_equal '10.0.2.1',                    header.sender_protocol_address
    assert_equal 'ff:ff:ff:ff:ff:ff',           header.target_hardware_address
    assert_equal '10.0.0.101',                  header.target_protocol_address
  end

  def test_ipv4_header
    capp = Capp.offline ICMP4_DUMP

    packet = capp.loop.first

    header = packet.ipv4_header

    assert_equal 4,              header.version
    assert_equal 5,              header.ihl
    assert_equal 0,              header.tos
    assert_equal 56,             header.length
    assert_equal 40436,          header.id
    assert_equal 0,              header.offset
    assert_equal 64,             header.ttl
    assert_equal 1,              header.protocol
    assert_equal 36729,          header.checksum
    assert_equal '10.101.28.65', header.source
    assert_equal '10.101.28.77', header.destination
  end

  def test_ipv6_header
    capp = Capp.offline ICMP6_DUMP

    packet = capp.loop.first

    header = packet.ipv6_header

    assert_equal                   6, header.version
    assert_equal                   0, header.traffic_class
    assert_equal          1610612736, header.flow_label
    assert_equal                  24, header.payload_length
    assert_equal                  58, header.next_header
    assert_equal                 255, header.hop_limit
    assert_equal                '::', header.source
    assert_equal 'ff02::1:ff48:eb73', header.destination
  end

  def test_icmp4_header
    capp = Capp.offline ICMP4_DUMP

    packet = capp.loop.first

    header = packet.icmp_header

    assert_equal     3, header.type
    assert_equal     3, header.code
    assert_equal 19056, header.checksum
  end

  def test_icmp6_header
    capp = Capp.offline ICMP6_DUMP

    packet = capp.loop.first

    header = packet.icmp_header

    assert_equal   135, header.type
    assert_equal     0, header.code
    assert_equal 45797, header.checksum
  end

  def test_loop
    capp = Capp.offline ICMP4_DUMP

    packets = []

    capp.loop do |packet|
      packets << packet
    end

    assert_equal 4, packets.size
  end

  def test_savefile_major_version
    major_version = Capp.offline(UDP4_DUMP).savefile_major_version

    assert_equal 2, major_version
  end

  def test_savefile_minor_version
    minor_version = Capp.offline(UDP4_DUMP).savefile_minor_version

    assert_equal 4, minor_version
  end

  def test_savefile_version
    version = Capp.offline(UDP4_DUMP).savefile_version

    assert_equal '2.4', version
  end

  def test_stats
    capp = Capp.offline ICMP4_DUMP

    capp.loop.to_a

    assert_raises Capp::Error do
      capp.stats
    end
  end

  def test_stop
    capp = Capp.offline ICMP4_DUMP

    packets = []

    capp.loop do |packet|
      packets << packet

      capp.stop
    end

    assert_equal 1, packets.size
  end

  def test_tcp4_header
    capp = Capp.offline TCP4_DUMP

    packet = capp.loop.first

    header = packet.tcp_header

    assert_equal     49475, header.source_port
    assert_equal      9091, header.destination_port
    assert_equal 192875902, header.seq_number
    assert_equal         0, header.ack_number
    assert_equal        11, header.offset
    assert_equal         2, header.flags
    assert_equal     65535, header.window
    assert_equal      7778, header.checksum
    assert_equal         0, header.urgent
  end

  def test_udp4_header
    capp = Capp.offline UDP4_DUMP

    packet = capp.loop.first

    header = packet.udp_header

    assert_equal 54938, header.source_port
    assert_equal  7647, header.destination_port
    assert_equal   105, header.length
    assert_equal  3147, header.checksum
  end

  def test_unknown_layer3_header
    capp = Capp.offline EAP_802_1X_DUMP

    packet = capp.loop.first

    header = packet.unknown_layer3_header

    assert_equal 14, header.payload_offset
  end

end

