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
# #loop yields a Capp::Packet.
#
# To stop capturing packets return from the loop.
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

  attr_reader :device

end

require 'capp/packet'
require 'capp/capp'

