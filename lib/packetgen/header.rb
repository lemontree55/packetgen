# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  # Namespace for protocol header classes
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
    def self.add_class(klass)
      protocol_name = klass.to_s.sub(/.*::/, '')
      @added_header_classes[protocol_name] = klass
      @header_classes = nil
    end

    # Remove a foreign header (previously added by {.add_header_class}à
    # from known header classes.
    # @param [Class] klass
    # @return [void]
    def self.remove_class(klass)
      protocol_name = klass.to_s.sub(/.*::/, '')
      @added_header_classes.delete protocol_name
      @header_classes = nil
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
