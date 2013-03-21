# -*- ruby -*-

require 'rubygems'
require 'hoe'
begin
  require 'rake/extensiontask'
rescue LoadError => e
  warn "missing #{e.path} (for rake-compiler)"
end

Hoe.plugin :minitest
Hoe.plugin :git

HOE = Hoe.spec 'pcap' do
  developer 'Eric Hodel', 'drbrain@segment7.net'

  rdoc_locations << 'docs.seattlerb.org:/data/www/docs.seattlerb.org/pcap/'

  self.readme_file = 'README.rdoc'

  self.extra_dev_deps << ['rake-compiler', '~> 0.8']
end

Rake::ExtensionTask.new 'pcap', HOE.spec do |ext|
  ext.lib_dir = 'lib/pcap'
end

# vim: syntax=ruby
