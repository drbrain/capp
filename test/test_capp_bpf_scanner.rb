require 'capp/test_case'

class TestCappBPFScanner < Capp::TestCase

  def test_next_token_escape
    assert_equal [:ID, 'foo'], scanner("\\foo") .next_token
  end

  def test_next_token_host_id
    assert_equal [:HID, '0.0'],     scanner('0.0').next_token
    assert_equal [:HID, '0.0.0'],   scanner('0.0.0').next_token
    assert_equal [:HID, '0.0.0.0'], scanner('0.0.0.0').next_token
  end

  def test_next_token_host_id_v6
    assert_equal [:HID6, '0::0'],     scanner('0::0').next_token
    assert_equal [:HID6, '0::0:0'],   scanner('0::0:0').next_token
    assert_equal [:HID6, '0::0:0:0'], scanner('0::0:0:0').next_token
  end

  def test_next_token_identifier
    assert_equal [:ID, 'foo'], scanner("foo").next_token
  end

  def test_next_token_mac_bad
    e = assert_raises RuntimeError do
      token = scanner('0::0::0::0::0::0').next_token

      flunk "matched bad MAC as #{token.inspect}"
    end

    assert_equal 'bogus ethernet address 0::0::0::0::0::', e.message
  end

  def test_next_token_mac_colon
    assert_equal [:EID, '0:0:0:0:0:0'], scanner('0:0:0:0:0:0').next_token

    assert_equal [:EID, '00:00:00:00:00:00'],
                 scanner('00:00:00:00:00:00').next_token
  end

  def test_next_token_mac_dash
    assert_equal [:EID, '0-0-0-0-0-0'], scanner('0-0-0-0-0-0').next_token

    assert_equal [:EID, '00-00-00-00-00-00'],
                 scanner('00-00-00-00-00-00').next_token
  end

  def test_next_token_number
    assert_equal [:AID, '1'], scanner('1').next_token
  end

  def test_next_token_whitespace
    assert_nil scanner(" ") .next_token
    assert_nil scanner("\n").next_token
    assert_nil scanner("\r").next_token
    assert_nil scanner("\t").next_token
  end

  def scanner text
    @scanner = Capp::BPF::Scanner.new
    @scanner.ss = @scanner.scanner_class.new text
    @scanner.lineno = 1
    @scanner.state ||= nil
    @scanner
  end

end

