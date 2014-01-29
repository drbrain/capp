require 'capp/test_case'
require 'etc'
require 'socket'
require 'thread'
require 'tmpdir'

class TestCappRoot < Capp::TestCase

  def setup
    @root = Etc.getpwuid

    skip 'this test must run as root' unless @root.uid == 0

    begin
      @nobody = Etc.getpwnam 'nobody'
    rescue ArgumentError
      skip 'this test require a "nobody" user"'
    end
  end

  def test_capp_devices
    devices = Capp.devices

    refute_empty devices

    device = devices.first

    assert_kind_of Capp::Device, device

    refute_empty device.addresses

    address = device.addresses.first

    assert_kind_of Capp::Address, address
  end

  def test_capp_drop_privileges_chroot
    Dir.mktmpdir 'capp' do |dir|
      fork_and_test do
        Capp.drop_privileges 'nobody', dir

        abort 'current directory unchanged' unless Dir.pwd == '/'

        begin
          File.stat dir
          abort 'choot failed'
        rescue Errno::ENOENT
        end

        exit! 0
      end
    end
  end

  def test_capp_drop_privileges_chroot_no_user
    Dir.mktmpdir 'capp' do |dir|
      e = assert_raises Capp::Error do
        Capp.drop_privileges nil, dir
      end

      assert_equal 'chroot without dropping root is insecure', e.message
    end
  end

  def test_capp_drop_privileges_chroot_nonexistent_dir
    Dir.mktmpdir 'capp' do |dir|
      nonexistent = File.join dir, 'nonexistent'
      e = assert_raises Capp::Error do
        Capp.drop_privileges 'nobody', nonexistent
      end

      assert_equal \
        "could not chroot to #{nonexistent} or change to chroot directory",
        e.message
    end
  end

  def test_capp_drop_privileges_name
    dir = Dir.pwd

    fork_and_test do
      Capp.drop_privileges 'nobody'

      user = Etc.getpwuid

      abort 'user unchanged'  if @root.uid == user.uid
      abort 'group unchanged' if @root.gid == user.gid

      begin
        File.stat dir
      rescue Errno::ENOENT
        abort 'unexpected chroot!'
      end

      exit! 0
    end
  end

  def test_capp_drop_privileges_no_user
    fork_and_test do
      Capp.drop_privileges nil

      user = Etc.getpwuid

      abort 'user changed'  unless @root.uid == user.uid
      abort 'group changed' unless @root.gid == user.gid

      exit! 0
    end
  end

  def test_capp_drop_privileges_nonexistent_user
    e = assert_raises Capp::Error do
      Capp.drop_privileges 'nonexistent'
    end

    assert_equal 'could not find user nonexistent', e.message
  end

  def test_capp_drop_privileges_uid
    dir = Dir.pwd

    fork_and_test do
      Capp.drop_privileges @nobody.uid

      user = Etc.getpwuid

      abort 'user unchanged'  if @root.uid == user.uid
      abort 'group unchanged' if @root.gid == user.gid

      begin
        File.stat dir
      rescue Errno::ENOENT
        abort 'unexpected chroot!'
      end

      exit! 0
    end
  end

  def test_capp_live
    loopback = Capp.devices.find do |device|
      device.addresses.any? do |address|
        address.address == '127.0.0.1'
      end
    end

    skip 'unable to find IPv4 loopback device' unless loopback

    capp = Capp.open loopback.name
    queue = Queue.new

    Thread.new do
      capp.loop do |packet|
        queue << packet
        break
      end
    end

    socket = UDPSocket.new
    socket.send 'hi', 0, '127.0.0.1', 54321
    socket.close

    packet = queue.pop

    assert_equal 'hi', packet.payload
  end

  def test_capp_device_open
    loopback = Capp.devices.find do |device|
      device.addresses.any? do |address|
        address.address == '127.0.0.1'
      end
    end

    skip 'unable to find IPv4 loopback device' unless loopback

    capp = loopback.open

    assert_equal loopback.name, capp.device
  end

  def fork_and_test
    pid = fork do
      yield
    end

    _, status = Process.wait2 pid

    assert status.success?, status.inspect
  end

end

