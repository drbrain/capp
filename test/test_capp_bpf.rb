require 'capp/test_case'

class TestCappBPF < Capp::TestCase

  def setup
    super

    @parser = Capp::BPF.new
  end

end

