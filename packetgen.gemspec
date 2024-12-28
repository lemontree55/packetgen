# coding: utf-8
# frozen_string_literal: true

require_relative 'lib/packetgen/version'

Gem::Specification.new do |spec|
  spec.name          = 'packetgen'
  spec.version       = PacketGen::VERSION
  spec.license       = 'MIT'
  spec.authors       = ['LemonTree55']
  spec.email         = ['lenontree@proton.me']

  spec.summary       = 'Network packet generator and dissector'
  spec.description   = <<~DESC
    PacketGen is a network packet manipulation library. It allows reading, parsing
    and sending network packets with fun.
  DESC

  spec.metadata = {
    'homepage_uri' => 'https://github.com/lemontree55/packetgen',
    'source_code_uri' => 'https://github.com/lemontree55/packetgen',
    'bug_tracker_uri' => 'https://github.com/lemontree55/packetgen/issues',
    'documentation_uri' => 'https://www.rubydoc.info/gems/packetgen',
    'wiki_uri' => 'https://github.com/lemontree55/packetgen/wiki'
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

  # Ruby 3.0
  spec.required_ruby_version = '>= 3.0.0'

  spec.add_dependency 'bin_struct', '~>0.3.0'
  spec.add_dependency 'digest-crc', '~> 0'
  spec.add_dependency 'interfacez', '~>1.0'
  spec.add_dependency 'pcaprub', '~>0.13.0'
  spec.add_dependency 'rasn1', '~>0.14'
end
