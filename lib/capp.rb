require 'socket'

##
# Capp is a GVL-friendly libpcap wrapper library.
#
# To create a packet capture device:
#
#   capp = Capp.live
#
# This listens on the default device.  You can list devices with Capp.devices.
#
# To start capture use #loop:
#
#   capp.loop do |packet|
#     # ...
#   end
#
# #loop yields a Capp::Packet object for each captured packet.
#
# To stop capturing packets return (or break) from the loop, or call #stop on
# the Capp instance.  You can resume capturing packets by calling #loop again
# after #stop.
#
# To set a filter for only udp port 7647 (Rinda::RingFinger packets):
#
#   capp.filter = 'udp port 7647'
#
# The format for a filter rule is the same as for tcpdump.  See the
# pcap-filter(7) man page for the filter syntax.
#
# You can use a Queue to capture packets in one thread and process them in
# another:
#
#   require 'capp'
#   require 'thread'
#
#   q = Queue.new
#
#   Thread.new do
#     while packet = q.deq do
#       # ...
#     end
#   end
#
#   capp = Capp.live.loop do |packet|
#     q.enq packet
#   end

class Capp

  ##
  # The version of Capp you are using

  VERSION = '1.0'

  ##
  # Error class for Capp errors

  class Error < RuntimeError
  end

  ##
  # An address for a Device which is returned by Capp::devices

  Address = Struct.new :address, :netmask, :broadcast, :destination

  ##
  # A device which Capp can listen on, returned by Capp::devices

  Device  = Struct.new :name, :description, :addresses, :flags

  ##
  # Device name packets are being captured from.  Only set for live packet
  # captures.

  attr_reader :device

  ##
  # Opens +device_or_file+ as an offline device if it is an IO or an existing
  # file.  +args+ are ignored (as ::offline does not support any).
  #
  # Opens +device_or_file+ as a live device otherwise, along with +args+.  See
  # ::live for documentation on the additional arguments.

  def self.open device_or_file, *args
    if IO === device_or_file or File.exist? device_or_file then
      offline device_or_file, *args
    else
      live device_or_file, *args
    end
  end

end

require 'capp/packet'
require 'capp/capp'

