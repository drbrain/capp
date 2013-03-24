# encoding: BINARY

require 'minitest/autorun'
require 'capp'

class TestCappPacket < MiniTest::Unit::TestCase

  def setup
    super

    @timestamp = Time.now
    @captured =
      "\x01\x00\x5e\x00\x00\xfb\x20\xc9\xd0\x48\xeb\x73\x08\x00\x45\x00" +
      "\x00\x39\xef\x92\x00\x00\x01\x11\xc2\x74\x0a\x65\x1c\x4d\xe0\x00" +
      "\x00\xfb\xfa\x0a\x14\xe9\x00\x25\x3a\x49\x02\x28\x01\x00\x00\x01" +
      "\x00\x00\x00\x00\x00\x00\x05\x6b\x61\x75\x6c\x74\x05\x6c\x6f\x63" +
      "\x61\x6c\x00\x00\x01\x00\x01"


    length = @captured.length

    @packet = Capp::Packet.new @timestamp, length, length, @captured
  end

  def test_dump
    expected = "..^... ..H"
    assert_equal expected, @packet.dump[0, 10]
  end

  def test_ethernet_header
    header = @packet.ethernet_header

    assert_equal 0x01_00_5e_00_00_fb, header.destination, 'destination'
    assert_equal 0x20_c9_d0_48_eb_73, header.source,      'source'
    assert_equal 0x0800,              header.ether_type,  'ether_type'
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

  def test_ip_payload
    expected = dump @captured[34, @captured.length]
    assert_equal expected, dump(@packet.ip_payload)
  end

  def test_ipv4_eh
    assert @packet.ipv4?
  end

  def test_ipv4_header
    header = @packet.ipv4_header

    assert_equal             4, header.version,         'version'
    assert_equal             5, header.ihl,             'ihl'
    assert_equal             0, header.dscp,            'dscp'
    assert_equal             0, header.ecn,             'ecn'
    assert_equal            57, header.length,          'length'
    assert_equal         61330, header.id,              'id'
    assert_equal             0, header.flags,           'flags'
    assert_equal             0, header.fragment_offset, 'fragment offset'
    assert_equal             1, header.ttl,             'ttl'
    assert_equal            17, header.protocol,        'protocol'
    assert_equal         49780, header.checksum,        'checksum'
    assert_equal 0x0a_65_1c_4d, header.source,          'source'
    assert_equal 0xe0_00_00_fb, header.destination,     'destination'
  end

  def test_udp_eh
    assert @packet.udp?
  end

  def test_udp_header
    header = @packet.udp_header

    assert_equal 64010, header.source_port,      'source_port'
    assert_equal  5353, header.destination_port, 'destination_port'
    assert_equal    37, header.length,           'length'
    assert_equal 14921, header.checksum,         'checksum'
  end

  def dump str
    str.tr "\000-\037\177-\377", "."
  end

end

