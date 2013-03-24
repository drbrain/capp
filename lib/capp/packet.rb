# coding: BINARY

class Capp::Packet

  UDP = Socket::IPPROTO_UDP

  EthernetHeader = Struct.new :destination, :source, :ether_type do
    def self.from_capture capture
      dst_a, dst_b, src_a, src_b, ether_type = capture.unpack 'nN nN n'

      destination = (dst_a << 32) + dst_b
      source      = (src_a << 32) + src_b

      new destination, source, ether_type
    end
  end

  IPv4Header = Struct.new :version, :ihl, :dscp, :ecn, :length,
                          :id, :flags, :fragment_offset,
                          :ttl, :protocol, :checksum,
                          :source, :destination do
    def self.from_capture capture
      vi, de, length, id, ffo, ttl, protocol, checksum, src, dst =
        capture.unpack '@14 C C n n n C C n N N'

      version = (vi & 0xf0) >> 4
      ihl     = (vi & 0x0f)

      dscp    = (de & 0xfc) >>  2
      ecn     = (de & 0x03)

      flags           = (ffo & 0xe000) >> 13
      fragment_offset = (ffo & 0x1fff)

      new version, ihl, dscp, ecn, length,
          id, flags, fragment_offset,
          ttl, protocol, checksum,
          src, dst
    end
  end

  UDPHeader = Struct.new :source_port, :destination_port, :length, :checksum do
    def self.from_capture capture
      vi, = capture.unpack '@14 C'

      offset = 14 + (vi & 0x0f) * 4

      src, dst, length, checksum = capture.unpack "@#{offset} n n n n"

      new src, dst, length, checksum
    end
  end

  attr_reader :timestamp
  attr_reader :length
  attr_reader :capture_length
  attr_reader :captured

  def initialize timestamp, length, capture_length, captured
    @capture_length = capture_length
    @captured       = captured
    @length         = length
    @timestamp      = timestamp

    @ethernet_header = nil
    @ipv4_header     = nil
  end

  def dump
    @captured.tr "\000-\037\177-\377", "."
  end

  def ethernet_header
    @ethernet_header ||=
      EthernetHeader.from_capture @captured
  end

  def hexdump offset = 0
    data = @captured[offset, @capture_length]

    data.scan(/.{,16}/m).map.with_index do |chunk, index|
      next nil if chunk.empty?
      hex  = chunk.unpack('C*').map { |byte| '%02x' % byte }
      dump = chunk.tr "\000-\037\177-\377", "."

      length = hex.length
      hex.fill '  ', length, 16 - length if length < 16

      "\t0x%04x:  %s%s %s%s %s%s %s%s %s%s %s%s %s%s %s%s  %s" % [
        index * 16, *hex, dump
      ]
    end.join "\n"
  end

  def ip_payload
    if ihl = ipv4? then
      @captured[14 + ihl * 4, @capture_length]
    else
      raise NotImplementedError
    end
  end

  def ipv4?
    vi = @captured.unpack('@14 C').first

    return false unless 64 == vi & 0xf0

    vi & 0x0f
  end

  def ipv4_header
    @ipv4_header ||= IPv4Header.from_capture @captured
  end

  def udp?
    ipv4? and ipv4_header.protocol == UDP
  end

  def udp_header
    @udp_header ||= UDPHeader.from_capture @captured
  end

end

