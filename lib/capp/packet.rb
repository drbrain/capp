# coding: BINARY

class Capp::Packet

  ##
  # 802.3 Ethernet header

  EthernetHeader = Struct.new :destination, :source, :type

  ##
  # ICMP header.  See RFC 792

  ICMPHeader = Struct.new :type, :code, :checksum, :data

  ##
  # IPv4 header.  See RFC 791

  IPv4Header = Struct.new :version, :ihl, :tos, :length,
                          :id, :offset,
                          :ttl, :protocol, :checksum,
                          :source, :destination
  ##
  # IPv6 header.  See RFC 2460

  IPv6Header = Struct.new :version, :traffic_class, :flow_label,
                          :payload_length, :next_header, :hop_limit,
                          :source, :destination


  ##
  # TCP header.  See RFC 793

  TCPHeader = Struct.new :source_port, :destination_port,
                         :seq_number, :ack_number,
                         :offset, :flags, :window, :checksum, :urgent

  ##
  # UDP header.  See RFC 768

  UDPHeader = Struct.new :source_port, :destination_port, :length, :checksum

  ##
  # Length of packet that was captured

  attr_reader :capture_length

  ##
  # Captured portion of the packet.

  attr_reader :captured

  ##
  # The Ethernet header

  attr_reader :ethernet_header

  ##
  # ICMP header

  attr_reader :icmp_header

  ##
  # IPv4 header

  attr_reader :ipv4_header

  ##
  # IPv6 header

  attr_reader :ipv6_header

  ##
  # Total length of packet

  attr_reader :length

  ##
  # TCP header

  attr_reader :tcp_header

  ##
  # Packet capture timestamp

  attr_reader :timestamp

  ##
  # UDP header

  attr_reader :udp_header

  ##
  # Creates a new packet.  Ordinarily this is performed from Capp#loop.  The
  # +timestamp+ is the packet capture timestamp, +length+ is the total length
  # of the packet, +capture_length+ is the number of captured bytes from the
  # packet.  The +datalink+ is the type of link the packet was captured on.
  # +headers+ is a Hash of parsed headers.

  def initialize timestamp, length, capture_length, captured, datalink, headers
    @capture_length = capture_length
    @captured       = captured
    @length         = length
    @timestamp      = timestamp
    @datalink       = datalink

    @ethernet_header = headers[:ethernet_header]
    @icmp_header     = headers[:icmp_header]
    @ipv4_header     = headers[:ipv4_header]
    @ipv6_header     = headers[:ipv6_header]
    @tcp_header      = headers[:tcp_header]
    @udp_header      = headers[:udp_header]
  end

  ##
  # Returns the destination of the packet regardless of protocol

  def destination
    destination =
      if ipv4? then
        @ipv4_header
      elsif ipv6? then
        @ipv6_header
      else
        raise NotImplementedError
      end.destination

    if tcp? then
      destination << ":#{@tcp_header.destination_port}"
    elsif udp? then
      destination << ":#{@udp_header.destination_port}"
    end

    destination
  end

  ##
  # Returns the captured bytes with non-printing characters replaced by "."

  def dump
    @captured.tr "\000-\037\177-\377", "."
  end

  ##
  # Dumps the captured packet from +offset+ with offsets, hexadecimal output
  # for the bytes and the ASCII content with non-printing characters replaced
  # by "."

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

  ##
  # The payload of the packet.  For a UDP packet captured from an Ethernet
  # interface this is payload after the Ethernet, IP and UDP headers.  For a
  # TCP packet captured from a loopback interface, this is the payload after
  # the protocol family, IP and TCP headers.

  def payload
    @captured[payload_offset, @capture_length]
  end

  ##
  # The offset into the captured data where the payload starts.

  def payload_offset
    offset =
      case @datalink
      when Capp::DLT_NULL then
        4
      when Capp::DLT_EN10MB then
        14
      end

    case
    when ipv4? then offset += @ipv4_header.ihl * 4
    when ipv6? then offset += 40
    else            raise NotImplementedError
    end

    case
    when tcp? then offset += @tcp_header.offset * 4
    when udp? then offset += 8
    else           raise NotImplementedError
    end

    offset
  end

  ##
  # Returns the source of the packet regardless of protocol

  def source
    source =
      if ipv4? then
        @ipv4_header
      elsif ipv6? then
        @ipv6_header
      else
        raise NotImplementedError
      end.source

    if tcp? then
      source << ":#{@tcp_header.source_port}"
    elsif udp? then
      source << ":#{@udp_header.source_port}"
    end

    source
  end

  ##
  # Is this an IPv4 packet?

  def ipv4?
    @ipv4_header
  end

  ##
  # Is this an IPv6 packet?

  def ipv6?
    @ipv6_header
  end

  ##
  # Is this a TCP packet?

  def tcp?
    @tcp_header
  end

  ##
  # Is this a UDP packet?

  def udp?
    @udp_header
  end

end

