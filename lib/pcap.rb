require 'socket'

class Pcap
  VERSION = '1.0'

  class Error < RuntimeError
  end

  Address = Struct.new :address, :netmask, :broadcast, :destination
  Device  = Struct.new :name, :description, :addresses, :loopback

end

require 'pcap/packet'
require 'pcap/pcap'

