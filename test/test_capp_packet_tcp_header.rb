require 'minitest/autorun'
require 'capp'

class TestCappPacketTCPHeader < Capp::TestCase

  def test_ack_eh
    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0xff, nil, nil, nil)

    assert header.ack?

    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0x00, nil, nil, nil)

    refute header.ack?
  end

  def test_cwr_eh
    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0xff, nil, nil, nil)

    assert header.cwr?

    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0x00, nil, nil, nil)

    refute header.cwr?
  end

  def test_ece_eh
    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0xff, nil, nil, nil)

    assert header.ece?

    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0x00, nil, nil, nil)

    refute header.ece?
  end

  def test_fin_eh
    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0xff, nil, nil, nil)

    assert header.fin?

    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0x00, nil, nil, nil)

    refute header.fin?
  end

  def test_push_eh
    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0xff, nil, nil, nil)

    assert header.push?

    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0x00, nil, nil, nil)

    refute header.push?
  end

  def test_rst_eh
    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0xff, nil, nil, nil)

    assert header.rst?

    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0x00, nil, nil, nil)

    refute header.rst?
  end

  def test_syn_eh
    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0xff, nil, nil, nil)

    assert header.syn?

    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0x00, nil, nil, nil)

    refute header.syn?
  end

  def test_urg_eh
    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0xff, nil, nil, nil)

    assert header.urg?

    header = Capp::Packet::TCPHeader.new(nil, nil, nil, nil,
                                         nil, 0x00, nil, nil, nil)

    refute header.urg?
  end

end

