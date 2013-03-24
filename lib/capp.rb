require 'socket'

class Capp
  VERSION = '1.0'

  class Error < RuntimeError
  end

  Address = Struct.new :address, :netmask, :broadcast, :destination
  Device  = Struct.new :name, :description, :addresses, :flags

end

require 'capp/packet'
require 'capp/capp'

