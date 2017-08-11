# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'packetgen/version'

Gem::Specification.new do |spec|
  spec.name          = 'packetgen'
  spec.version       = PacketGen::VERSION
  spec.authors       = ['Sylvain Daubert']
  spec.email         = ['sylvain.daubert@laposte.net']

  spec.summary       = %q{Network packet generator and analyzor}
  #spec.description   = %q{TODO: Write a longer description or delete this line.}
  spec.homepage      = 'https://github.com/sdaubert/packetgen'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'bin'
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.1.0'

  spec.add_dependency 'pcaprub', '~>0.12.4'
  spec.add_dependency 'pry', '~>0.10'
  spec.add_dependency 'network_interface'
  spec.add_dependency 'net-proto', '~>1.2'
  spec.add_dependency 'rasn1', '~>0.3', '>= 0.3.1'

  spec.add_development_dependency 'bundler', '~> 1.7'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'simplecov', '~> 0.12'
  spec.add_development_dependency 'yard', '~> 0.9'
end
