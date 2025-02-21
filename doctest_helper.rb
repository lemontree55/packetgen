# frozen_string_literal: true

require 'packetgen'
require 'packetgen/utils'

YARD::Doctest.configure do |doctest|
  doctest.skip 'PacketGen.header'
  doctest.skip 'PacketGen::Utils'

  doctest.before 'PacketGen::PacpNG::File' do
    pkt1 = PacketGen.gen('IP', id: 1).add('TCP')
    pkt2 = PacketGen.gen('IP', id: 2).add('UDP')
    file = PacketGen::PcapNG::File.new
    file.read_array([pkt1, pkt2])
    file.write('/tmp/file.pcapng')
  end

  doctest.after 'PacketGen::PacpNG::File' do
    File.unlink('/tmp/file.pcapng')
  end
end
