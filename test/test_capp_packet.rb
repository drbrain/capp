# encoding: BINARY

require 'minitest/autorun'
require 'capp'
require 'resolv'
require 'tempfile'

class TestCappPacket < MiniTest::Unit::TestCase

  def setup
    super

    @CP = Capp::Packet

    @timestamp = Time.now
    @captured =
      "\x01\x00\x5e\x00\x00\xfb\x20\xc9\xd0\x48\xeb\x73\x08\x00\x45\x00" +
      "\x00\x39\xef\x92\x00\x00\x01\x11\xc2\x74\x0a\x65\x1c\x4d\xe0\x00" +
      "\x00\xfb\xfa\x0a\x14\xe9\x00\x25\x3a\x49\x02\x28\x01\x00\x00\x01" +
      "\x00\x00\x00\x00\x00\x00\x05\x6b\x61\x75\x6c\x74\x05\x6c\x6f\x63" +
      "\x61\x6c\x00\x00\x01\x00\x01"


    length = @captured.length

    @headers = {
      ethernet_header:
        @CP::EthernetHeader.new(0x01_00_5e_00_00_fb, 0x20_c9_d0_48_eb_73,
                                0x0800),
      ipv4_header:
        @CP::IPv4Header.new(4, 5, 0, 57, 61330, 0, 1, 17, 49780,
                            '10.101.28.77', '224.0.0.251'),
      udp_header:
        @CP::UDPHeader.new(64010, 5353, 37, 14921),
    }

    @packet =
      @CP.new @timestamp, length, length, @captured, Capp::DLT_EN10MB, @headers
  end

  def test_destination_resolver
    assert_equal 'mdns.mcast.net.5353', @packet.destination(resolver)

    @packet.ipv4_header.destination = '192.0.2.1'

    assert_equal '192.0.2.1.5353', @packet.destination(resolver)
  end

  def test_destination_udp4
    assert_equal '224.0.0.251.5353', @packet.destination
  end

  def test_dump
    expected = '..^... ..H'
    assert_equal expected, @packet.dump[0, 10]
  end

  def test_ethernet_header
    header = @packet.ethernet_header

    assert_equal 0x01_00_5e_00_00_fb, header.destination, 'destination'
    assert_equal 0x20_c9_d0_48_eb_73, header.source,      'source'
    assert_equal 0x0800,              header.type,        'type'
  end

  def test_hexdump
    expected = <<-EXPECTED
\t0x0000:  0100 5e00 00fb 20c9 d048 eb73 0800 4500  ..^... ..H.s..E.
\t0x0010:  0039 ef92 0000 0111 c274 0a65 1c4d e000  .9.......t.e.M..
\t0x0020:  00fb fa0a 14e9 0025 3a49 0228 0100 0001  .......%:I.(....
\t0x0030:  0000 0000 0000 056b 6175 6c74 056c 6f63  .......kault.loc
\t0x0040:  616c 0000 0100 01                        al.....
    EXPECTED

    assert_equal expected, @packet.hexdump
  end

  def test_hexdump_offset
    expected = <<-EXPECTED
\t0x0000:  4500 0039 ef92 0000 0111 c274 0a65 1c4d  E..9.......t.e.M
\t0x0010:  e000 00fb fa0a 14e9 0025 3a49 0228 0100  .........%:I.(..
\t0x0020:  0001 0000 0000 0000 056b 6175 6c74 056c  .........kault.l
\t0x0030:  6f63 616c 0000 0100 01                   ocal.....
    EXPECTED

    assert_equal expected, @packet.hexdump(14)
  end

  def test_payload
    expected = dump @captured[42, @captured.length]
    assert_equal expected, dump(@packet.payload)
  end

  def test_ipv4_eh
    assert @packet.ipv4?
  end

  def test_ipv6_eh
    refute @packet.ipv6?
  end

  def test_source_resolver
    assert_equal 'kault.64010', @packet.source(resolver)

    @packet.ipv4_header.source = '192.0.2.1'

    assert_equal '192.0.2.1.64010', @packet.source(resolver)
  end

  def test_source_udp4
    assert_equal '10.101.28.77.64010', @packet.source
  end

  def test_udp_eh
    assert @packet.udp?
  end

  def dump str
    str.tr "\000-\037\177-\377", "."
  end

  def resolver
    io = Tempfile.open 'hosts' do |io|
      io.puts '224.0.0.251 mdns.mcast.net'
      io.puts '10.101.28.77 kault'
      io.flush

      resolver = Resolv::Hosts.new io.path
      resolver.getname '224.0.0.251' # initialize
      resolver
    end
  end

end

