# coding: utf-8
# frozen_string_literal: true

require_relative 'lib/packetgen/version'

Gem::Specification.new do |spec|
  spec.name          = 'packetgen'
  spec.version       = PacketGen::VERSION
  spec.license       = 'MIT'
  spec.authors       = ['Sylvain Daubert']
  spec.email         = ['sylvain.daubert@laposte.net']

  spec.summary       = 'Network packet generator and dissector'
  spec.description   = <<~DESC
    PacketGen is a network packet manipulation library. It allows reading, parsing
    and sending network packets with fun.
  DESC

  spec.metadata = {
    'homepage_uri' => 'https://github.com/sdaubert/packetgen',
    'source_code_uri' => 'https://github.com/sdaubert/packetgen',
    'bug_tracker_uri' => 'https://github.com/sdaubert/packetgen/issues',
    'documentation_uri' => 'https://www.rubydoc.info/gems/packetgen',
    'wiki_uri' => 'https://github.com/sdaubert/packetgen/wiki'
  }

  spec.files = Dir['lib/**/*']
  spec.bindir        = 'bin'
  spec.executables   = %w[pgconsole]

  spec.extra_rdoc_files = Dir['README.md', 'LICENSE']
  spec.rdoc_options += [
    '--title', 'PacketGen - network packet dissector',
    '--main', 'README.md',
    '--inline-source',
    '--quiet'
  ]

  spec.required_ruby_version = '>= 2.7.0'

  spec.add_dependency 'interfacez', '~>1.0'
  spec.add_dependency 'pcaprub', '~>0.13.0'
  spec.add_dependency 'rasn1', '~>0.12'
end
