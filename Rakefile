# -*- ruby -*-

require 'rubygems'
require 'hoe'
begin
  require 'rake/extensiontask'
rescue LoadError => e
  warn "\nmissing #{e.path} (for rake-compiler)" if e.respond_to? :path
  warn "run: rake newb\n\n"
end

Hoe.plugin :git
Hoe.plugin :minitest
Hoe.plugin :travis

HOE = Hoe.spec 'capp' do
  developer 'Eric Hodel', 'drbrain@segment7.net'

  rdoc_locations << 'docs.seattlerb.org:/data/www/docs.seattlerb.org/capp/'

  self.extra_rdoc_files << 'ext/capp/capp.c'
  self.spec_extras[:extensions] = 'ext/capp/extconf.rb'

  self.readme_file = 'README.rdoc'

  self.extra_dev_deps << ['rake-compiler', '~> 0.8']
end

if Rake.const_defined? :ExtensionTask then
  Rake::ExtensionTask.new 'capp', HOE.spec do |ext|
    ext.lib_dir = 'lib/capp'
  end

  task test: :compile
end

namespace :travis do
  task :install_libpcap do
    sh 'sudo apt-get install libpcap-dev'
  end

  Rake::TestTask.new root_test: %w[compile] do |t|
    t.libs << 'lib'
    t.test_files = FileList['test/test_capp_root.rb']
  end

  task :run_root_test do
    ruby = Gem.ruby
    sh 'sudo', ruby, '-S', 'rake', '-t', 'travis:root_test'
  end

  task before: %w[install_libpcap]
end

task travis: %w[travis:run_root_test]

# vim: syntax=ruby
