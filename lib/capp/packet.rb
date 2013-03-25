# coding: BINARY

class Capp::Packet

  UDP = Socket::IPPROTO_UDP

  EthernetHeader = Struct.new :destination, :source, :type

  IPv4Header = Struct.new :version, :ihl, :tos, :length,
                          :id, :offset,
                          :ttl, :protocol, :checksum,
                          :source, :destination, :payload_offset

  TCPHeader = Struct.new :source_port, :destination_port,
                         :sequence_number, :acknowledgement_number,
                         :offset, :flags, :window, :checksum, :urgent

  UDPHeader = Struct.new :source_port, :destination_port, :length, :checksum

  attr_reader :capture_length
  attr_reader :captured
  attr_reader :ethernet_header
  attr_reader :ipv4_header
  attr_reader :length
  attr_reader :tcp_header
  attr_reader :timestamp
  attr_reader :udp_header

  def initialize timestamp, length, capture_length, captured, headers
    @capture_length = capture_length
    @captured       = captured
    @length         = length
    @timestamp      = timestamp

    @ethernet_header = headers[:ethernet_header]
    @ipv4_header     = headers[:ipv4_header]
    @tcp_header      = headers[:tcp_header]
    @udp_header      = headers[:udp_header]
  end

  def dump
    @captured.tr "\000-\037\177-\377", "."
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
    @ipv4_header
  end

  def udp?
    ipv4? and ipv4_header.protocol == UDP
  end

end

