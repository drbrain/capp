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

HOE = Hoe.spec 'capp' do
  developer 'Eric Hodel', 'drbrain@segment7.net'

  rdoc_locations << 'docs.seattlerb.org:/data/www/docs.seattlerb.org/capp/'

  self.extra_rdoc_files << 'ext/capp/capp.c'

  self.readme_file = 'README.rdoc'

  self.extra_dev_deps << ['rake-compiler', '~> 0.8']
end

Rake::ExtensionTask.new 'capp', HOE.spec do |ext|
  ext.lib_dir = 'lib/capp'
end

task test: :compile

# vim: syntax=ruby
