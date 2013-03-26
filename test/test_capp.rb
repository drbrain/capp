require 'minitest/autorun'
require 'capp'

class TestCapp < MiniTest::Unit::TestCase
  
  ICMP_DUMP = File.expand_path '../icmp.pcap', __FILE__

  def setup
    super
  end

  def test_loop
    capp = Capp.offline ICMP_DUMP

    packets = []

    capp.loop do |packet|
      packets << packet
    end

    assert_equal 4, packets.size
  end

end

