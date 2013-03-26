require 'minitest/autorun'
require 'capp'

class TestCapp < MiniTest::Unit::TestCase
  
  ICMP_DUMP = File.expand_path '../icmp.pcap', __FILE__

  def setup
    super
  end

  def test_class_offline_file
    open ICMP_DUMP do |io|
      capp = Capp.offline io

      assert capp.loop.first
    end
  end

  def test_class_offline_filename
    capp = Capp.offline ICMP_DUMP

    assert capp.loop.first
  end

  def test_filter_equals
    capp = Capp.offline ICMP_DUMP

    capp.filter = 'icmp[icmptype] = icmp-echo'

    assert_equal 2, capp.loop.count
  end

  def test_filter_equals_garbage
    capp = Capp.offline ICMP_DUMP

    assert_raises Capp::Error do
      capp.filter = 'garbage'
    end
  end

  def test_loop
    capp = Capp.offline ICMP_DUMP

    packets = []

    capp.loop do |packet|
      packets << packet
    end

    assert_equal 4, packets.size
  end

  def test_stats
    capp = Capp.offline ICMP_DUMP

    capp.loop.to_a

    assert_raises Capp::Error do
      capp.stats
    end
  end

end

