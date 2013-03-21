class Pcap
  VERSION = '1.0'

  class Error < RuntimeError
  end

end

require 'pcap/packet'
require 'pcap/pcap'

