require 'minitest/autorun'
require 'capp'

class TestCapp < MiniTest::Unit::TestCase
  
  ICMP4_DUMP = File.expand_path '../icmp4.pcap', __FILE__
  TCP4_DUMP  = File.expand_path '../tcp4.pcap',  __FILE__
  UDP4_DUMP  = File.expand_path '../udp4.pcap',  __FILE__

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

  def test_ethernet_header
    capp = Capp.offline UDP4_DUMP

    packet = capp.loop.first

    header = packet.ethernet_header

    assert_equal 'ff:ff:ff:ff:ff:ff', header.destination
    assert_equal '20:c9:d0:48:eb:73', header.source
    assert_equal              0x0800, header.type
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
    assert_equal nil,            header.payload_offset
  end

  def test_loop
    capp = Capp.offline ICMP4_DUMP

    packets = []

    capp.loop do |packet|
      packets << packet
    end

    assert_equal 4, packets.size
  end

  def test_stats
    capp = Capp.offline ICMP4_DUMP

    capp.loop.to_a

    assert_raises Capp::Error do
      capp.stats
    end
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

end

