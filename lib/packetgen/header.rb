# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  # Namespace for protocol header classes
  # == Add a foreign header class
  # Since v1.1.0, PacketGen permits adding you own header classes.
  # First, define the new header class. By example:
  #  module MyModule
  #    class MyHeader < Struct.new(:field1, :field2)
  #      include PacketGen::StructFu
  #      include PacketGen::Header::HeaderMethods
  #      extend PacketGen::Header::HeaderClassMethods
  #      
  #      def initialize(options={})
  #        super Int32.new(options[:field1]), Int32.new(options[:field2])
  #      end
  #      
  #      def read(str)
  #        self[:field1].read str[0, 4]
  #        self[:field2].read str[4, 4]
  #      end
  #    end
  #   end
  # Then, class must be declared to PacketGen:
  #  PacketGen::Header.add_class MyModule::MyHeader
  # Finally, bindings must be declared:
  #  # bind MyHeader as IP protocol number 254 (needed by Packet#parse)
  #  PacketGen::Header::IP.bind_header MyModule::MyHeader, protocol: 254
  # And use it:
  #  pkt = Packet.gen('IP').add('MyHeader', field1: 0x12345678)
  #  pkt.myheader.field2.read 0x01
  # @author Sylvain Daubert
  module Header

    @added_header_classes = {}

    # Get known header classes
    # @return [Array<Class>]
    def self.all
      return @header_classes if @header_classes

      @builtin ||= constants.map { |sym| const_get sym }.
                 select { |klass| klass < Struct && klass < HeaderMethods }
      @header_classes = @builtin + @added_header_classes.values
    end

    # Add a foreign header class to known header classes. This is
    # needed by {Packet.gen} and {Packet#add}.
    # @param [Class] klass a header class, which should include
    #   {Header::HeaderMethods} and {Header::HeaderClassMethods}
    # @return [void]
    # @since 1.1.0
    def self.add_class(klass)
      protocol_name = klass.to_s.sub(/.*::/, '')
      @added_header_classes[protocol_name] = klass
      @header_classes = nil
    end

    # Remove a foreign header (previously added by {.add_header_class}à
    # from known header classes.
    # @param [Class] klass
    # @return [void]
    # @since 1.1.0
    def self.remove_class(klass)
      protocol_name = klass.to_s.sub(/.*::/, '')
      @added_header_classes.delete protocol_name
      @header_classes = nil
    end

    # Get header class from its name
    # @param [String] name
    # @return [Class,nil]
    # @since 1.1.0
    def self.get_header_class_by_name(name)
      if Header.const_defined? name
        Header.const_get name
      else
        @added_header_classes[name]
      end
    end
  end
end

require_relative 'header/header_class_methods'
require_relative 'header/header_methods'
require_relative 'header/eth'
require_relative 'header/ip'
require_relative 'header/icmp'
require_relative 'header/arp'
require_relative 'header/ipv6'
require_relative 'header/icmpv6'
require_relative 'header/udp'
require_relative 'header/tcp'
require_relative 'header/esp'
