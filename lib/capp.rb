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

  Device = Struct.new :name, :description, :addresses, :flags do

    ##
    # Creates a new packet capture device for this device sending the given
    # +args+ to Capp.open.

    def open *args
      Capp.open name, *args
    end

  end

  ##
  # Device name packets are being captured from.  Only set for live packet
  # captures.

  attr_reader :device

  ##
  # Drops root privileges to the given +run_as_user+ and optionally chroots to
  # +run_as_directory+.  Use this method after creating a packet capture
  # instance to improve security.
  #
  # Returns true if privileges are dropped, raises a Capp::Error if privileges
  # could not be dropped and returns a false value if there was no need to
  # drop privileges.
  #
  # You will be able to start and stop packet capture but not create new
  # packet capture instances after dropping privileges.

  def self.drop_privileges run_as_user, run_as_directory = nil
    return unless Process.uid.zero? and Process.euid.zero?
    return unless run_as_user or run_as_directory

    raise Capp::Error, 'chroot without dropping root is insecure' if
      run_as_directory and not run_as_user

    require 'etc'

    begin
      pw = if Integer === run_as_user then
             Etc.getpwuid run_as_user
           else
             Etc.getpwnam run_as_user
           end
    rescue ArgumentError => e
      raise Capp::Error, "could not find user #{run_as_user}"
    end

    if run_as_directory then
      begin
        Dir.chroot run_as_directory
        Dir.chdir '/'
      rescue Errno::ENOENT => e
        raise Capp::Error, "could not chroot to #{run_as_directory} " +
                           "or change to chroot directory"
      end
    end

    begin
      Process.gid = pw.gid
      Process.uid = pw.uid
    rescue Errno::EPERM => e
      raise Capp::Error, "unable to drop privileges to #{run_as_user} " +
                         "(#{e.message})"
    end

    true
  end

  ##
  # Opens +device_or_file+ as an offline device if it is an IO or an existing
  # file.  +args+ are ignored (as ::offline does not support any).
  #
  # Opens +device_or_file+ as a live device otherwise, along with +args+.  See
  # ::live for documentation on the additional arguments.

  def self.open device_or_file, *args
    if Capp::Device === device_or_file then
      device_or_file.open *args
    elsif IO === device_or_file or File.exist? device_or_file then
      offline device_or_file, *args
    else
      live device_or_file, *args
    end
  end

  ##
  # When called on a capture instance created from a savefile, returns the
  # version of the savefile.  When called on a live capture instance it
  # returns a meaningless value.

  def savefile_version
    "#{savefile_major_version}.#{savefile_minor_version}"
  end

end

require 'capp/bpf'
require 'capp/packet'
require 'capp/capp'

