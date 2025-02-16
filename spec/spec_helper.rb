# frozen_string_literal: true

Warning[:deprecated] = true

begin
  require 'simplecov'
  SimpleCov.start do
    add_filter '/spec/'
    add_filter '/vendor/'
  end

  RSpec.configure do |c|
    if c.filter[:sudo]
      SimpleCov.command_name 'rspec:sudo'
    else
      SimpleCov.command_name 'rspec'
    end
  end
rescue LoadError
  nil
end

$LOAD_PATH.unshift File.join(File.dirname(__FILE__), '..', 'lib')
require 'packetgen'

Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].sort.each { |f| require f }

RSpec.configure do |c|
  c.include CaptureHelper
  c.include BindingHelper
  c.include LabelHelper
end

def read_packets(filename)
  PacketGen::PcapNG::File.new.read_packets(File.join(__dir__, 'header', filename))
end

def read_raw_packets(filename)
  PacketGen::PcapNG::File.new.read_packet_bytes(File.join(__dir__, 'header', filename))
end
