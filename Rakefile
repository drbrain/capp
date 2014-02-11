# -*- ruby -*-

require 'rubygems'
require 'hoe'
begin
  require 'rake/extensiontask'
rescue LoadError => e
  warn "\nmissing #{e.path} (for rake-compiler)" if e.respond_to? :path
  warn "run: rake newb\n\n"
end

PARSER_FILES = %w[
  lib/capp/bpf.rb
  lib/capp/bpf/scanner.rex.rb
]

Hoe.plugin :git
Hoe.plugin :minitest
Hoe.plugin :travis

HOE = Hoe.spec 'capp' do
  developer 'Eric Hodel', 'drbrain@segment7.net'
  license 'MIT'

  rdoc_locations << 'docs.seattlerb.org:/data/www/docs.seattlerb.org/capp/'

  self.clean_globs += PARSER_FILES

  self.extra_rdoc_files << 'ext/capp/capp.c'
  self.spec_extras[:extensions] = 'ext/capp/extconf.rb'

  self.readme_file = 'README.rdoc'

  dependency 'rake-compiler', '~> 0.8', :developer
  dependency 'racc',          '~> 1.4', :developer
  dependency 'oedipus_lex',   '~> 2.1', :developer
end

if Rake.const_defined? :ExtensionTask then
  HOE.spec.files.delete_if { |file| file == '.gemtest' }

  Rake::ExtensionTask.new 'capp', HOE.spec do |ext|
    ext.lib_dir = 'lib/capp'
  end

  task test: :compile
end

task generate: :parser
task parser:   [:lexer, 'lib/capp/bpf.rb']
task lexer:    'lib/capp/bpf/scanner.rex.rb'

task default: :generate
task test:    :generate

begin
  require 'oedipus_lex'
  Rake.application.rake_require 'oedipus_lex'
rescue LoadError => e
  warn "\nmissing #{e.path} (for oedipus_lex)" if e.respond_to? :path
  warn "run: rake newb\n\n"
end

rule '.rb' => '.ry' do |t|
  racc = Gem.bin_path 'racc', 'racc'

  ruby "-rubygems #{racc} -t -l -o #{t.name} #{t.source}"
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
    sh 'sudo', '-E', ruby, '-S', 'rake', '-t', 'travis:root_test'
  end

  task before: %w[install_libpcap]
end

task travis: %w[travis:run_root_test]

# vim: syntax=ruby
