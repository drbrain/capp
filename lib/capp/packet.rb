# coding: BINARY

##
# Capp::Packet provides convenient extraction of data from packets.
#
# Packet objects are automatically created when a packet is read from the
# opened interface.  Unfortunately Capp does not understand every type of
# packet.  If Capp doesn't understand your packet the layer 3 payload can be
# retrieved from unknown_layer3_header.
#
# If Capp doesn't understand your packets you can extract the data by editing
# capp.c and submitting a patch.  See README for the source code location.
#
# To look up IP source and destination names Resolv (from the ruby standard
# library, require 'resolv') to avoid blocking on name lookups in a
# cross-platform manner.

class Capp::Packet

  ADDRESS_CACHE = {} # :nodoc:

  ##
  # ARP header.  See RFC 826

  ARPHeader = Struct.new :hardware, :protocol, :operation,
                         :sender_hardware_address, :sender_protocol_address,
                         :target_hardware_address, :target_protocol_address do
    alias sha sender_hardware_address
    alias spa sender_protocol_address
    alias tha target_hardware_address
    alias tpa target_protocol_address
  end

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
                         :offset, :flags, :window, :checksum, :urgent do

    alias source      source_port
    alias destination destination_port

    ##
    # Is the acknowledgment flag set?

    def ack?
      Capp::TCP_ACK == flags & Capp::TCP_ACK
    end

    ##
    # Is the congestion window reduced flag set?

    def cwr?
      Capp::TCP_CWR == flags & Capp::TCP_CWR
    end

    ##
    # Is the explicit congestion notification echo flag set?

    def ece?
      Capp::TCP_ECE == flags & Capp::TCP_ECE
    end

    ##
    # Is the no-more-data flag set?

    def fin?
      Capp::TCP_FIN == flags & Capp::TCP_FIN
    end

    ##
    # Is the push flag set?

    def push?
      Capp::TCP_PUSH == flags & Capp::TCP_PUSH
    end

    ##
    # Is the reset flag set?

    def rst?
      Capp::TCP_RST == flags & Capp::TCP_RST
    end

    ##
    # Is the synchronize flag set?

    def syn?
      Capp::TCP_SYN == flags & Capp::TCP_SYN
    end

    ##
    # Is the urgent flag set?

    def urg?
      Capp::TCP_URG == flags & Capp::TCP_URG
    end

  end

  ##
  # UDP header.  See RFC 768

  UDPHeader = Struct.new :source_port, :destination_port, :length, :checksum do
    alias source      source_port
    alias destination destination_port
  end

  ##
  # Fake header for an unknown layer 3 protocol.  See also
  # Capp::Packet#unknown_layer3_header

  UnknownLayer3Header = Struct.new :payload_offset

  ##
  # Length of packet that was captured

  attr_reader :capture_length

  ##
  # Captured portion of the entire packet including datalink layer.

  attr_reader :captured

  ##
  # The ARP header if this is an ARP packet.

  attr_reader :arp_header

  ##
  # The Ethernet header if this is an Ethernet packet.

  attr_reader :ethernet_header

  ##
  # Array of protocol names in this packet.  This list is ordered from lowest
  # to highest level.

  attr_reader :protocols

  ##
  # ICMP header if this is an ICMP (v4) packet.

  attr_reader :icmp_header

  ##
  # IPv4 header if this is an IPv4 packet.

  attr_reader :ipv4_header

  ##
  # IPv6 header if this is an IPv6 packet.

  attr_reader :ipv6_header

  ##
  # Total length of packet including the portion not captured.

  attr_reader :length

  ##
  # TCP header if this is a TCP packet.

  attr_reader :tcp_header

  ##
  # Packet capture timestamp

  attr_reader :timestamp

  ##
  # UDP header if this is a UDP packet.

  attr_reader :udp_header

  ##
  # Fake header for unknown layer 3 protocols.  The datalink type will
  # indicate the layer 3 protocol.  For an Ethernet packet see the
  # ethernet_header for the type, etc.  This method only provides the payload
  # offset of the packet content.

  attr_reader :unknown_layer3_header

  ##
  # Creates a new packet.  Ordinarily this is performed from Capp#loop.  The
  # +timestamp+ is the packet capture timestamp, +length+ is the total length
  # of the packet, +capture_length+ is the number of captured bytes from the
  # packet.  The +datalink+ is the type of link the packet was captured on.
  # +headers+ is a Hash of parsed headers.

  def initialize timestamp, length, capture_length, captured, datalink, headers
    @capture_length = capture_length
    @captured       = captured
    @datalink       = datalink
    @length         = length
    @protocols      = headers.keys
    @timestamp      = timestamp

    @arp_header            = headers[:arp]
    @ethernet_header       = headers[:ethernet]
    @icmp_header           = headers[:icmp]
    @ipv4_header           = headers[:ipv4]
    @ipv6_header           = headers[:ipv6]
    @tcp_header            = headers[:tcp]
    @udp_header            = headers[:udp]
    @unknown_layer3_header = headers[:unknown_layer3]
  end

  ##
  # Returns the destination of the packet regardless of protocol
  #
  # If a Resolv-compatible +resolver+ is given the name will be looked up.

  def destination resolver = nil
    destination =
      if ipv4? then
        @ipv4_header
      elsif ipv6? then
        @ipv6_header
      else
        raise NotImplementedError
      end.destination

    destination = resolve destination, resolver

    if tcp? then
      destination << ".#{@tcp_header.destination_port}"
    elsif udp? then
      destination << ".#{@udp_header.destination_port}"
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
  # The payload of the packet.
  #
  # For example, for a UDP packet captured from an Ethernet interface this is
  # payload after the Ethernet, IP and UDP headers

  def payload
    @captured[payload_offset, @capture_length]
  end

  ##
  # The offset into the captured data where the payload starts.
  #
  # Note that this method does not work properly for IPv6 packets with options
  # set, but I have yet to encounter such an example in the wild.

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

  def resolve address, resolver # :nodoc:
    return address.dup unless resolver

    if name = ADDRESS_CACHE[address] then
      return name.dup
    end

    name = resolver.getname address

    ADDRESS_CACHE[address] = name

    name.dup
  rescue Resolv::ResolvError
    ADDRESS_CACHE[address] = address
    address.dup
  end

  ##
  # Returns the source of the packet regardless of protocol.
  #
  # If a Resolv-compatible +resolver+ is given the name will be looked up.

  def source resolver = nil
    source =
      if ipv4? then
        @ipv4_header
      elsif ipv6? then
        @ipv6_header
      else
        raise NotImplementedError
      end.source.dup

    source = resolve source, resolver

    if tcp? then
      source << ".#{@tcp_header.source_port}"
    elsif udp? then
      source << ".#{@udp_header.source_port}"
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

