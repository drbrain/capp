# encoding: BINARY

require 'minitest/autorun'
require 'pcap'

class TestPcapPacket < MiniTest::Unit::TestCase

  def setup
    super

    @timestamp = Time.now
    @captured =
      "\0\0$\xCFn6 \xC9\xD0H\xEBs\b\0E\0\0ZAB\0\0\xFF\x11-9\ne\x1CM\ne" +
      "\x1C\x01\xD8.\05\0F\xA1\x8C\x0F\x06\x01\0\0\x01\0\0\0\0\0\0\x05" +
      "e3191\x01c\nakamaiedge\x03net\x010\x011\x02cn\nakamaiedge\x03net" +
      "\0\0\x01\0\x01"

    length = @captured.length

    @packet = Pcap::Packet.new @timestamp, length, length, @captured
  end

  def test_dump
    expected = "..$.n6 ..H"
    assert_equal expected, @packet.dump[0, 10]
  end

  def test_ethernet_header
    header = @packet.ethernet_header

    assert_equal 0x00_00_24_cf_6e_36, header.destination, 'destination'
    assert_equal 0x20_c9_d0_48_eb_73, header.source,      'source'
    assert_equal 0x0800,              header.ether_type,  'ether_type'
  end

  def test_hexdump
    expected = <<-EXPECTED
\t0x0000:  0000 24cf 6e36 20c9 d048 eb73 0800 4500  ..$.n6 ..H.s..E.
\t0x0010:  005a 4142 0000 ff11 2d39 0a65 1c4d 0a65  .ZAB....-9.e.M.e
\t0x0020:  1c01 d82e 0500 46a1 8c0f 0601 0000 0100  ......F.........
\t0x0030:  0000 0000 0005 6533 3139 3101 630a 616b  ......e3191.c.ak
\t0x0040:  616d 6169 6564 6765 036e 6574 0130 0131  amaiedge.net.0.1
\t0x0050:  0263 6e0a 616b 616d 6169 6564 6765 036e  .cn.akamaiedge.n
\t0x0060:  6574 0000 0100 01                        et.....
    EXPECTED

    assert_equal expected, @packet.hexdump
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
    assert_equal            90, header.length,          'length'
    assert_equal         16706, header.id,              'id'
    assert_equal             0, header.flags,           'flags'
    assert_equal             0, header.fragment_offset, 'fragment offset'
    assert_equal           255, header.ttl,             'ttl'
    assert_equal            17, header.protocol,        'protocol'
    assert_equal         11577, header.checksum,        'checksum'
    assert_equal 0x0a_65_1c_4d, header.source,          'source'
    assert_equal 0x0a_65_1c_01, header.destination,     'destination'
  end

  def dump str
    str.tr "\000-\037\177-\377", "."
  end

end

