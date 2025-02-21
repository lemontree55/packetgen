# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  # This mixin module defines minimal API for a class to act as a header
  # in {Packet}.
  #
  # Some others methods may optionally be defined by a {Headerable} object:
  # * +#calc_length+ to calculate length from content. It should be defined if header as a length attribute.
  # * +#calc_checksum+ to calculate checksum. It should be defined if header as a checksum attriibute.
  # * +#reply+ to invert fields in header for a reply.
  # @author Sylvain Daubert
  # @author LemonTree55
  # @since 3.0.2
  module Headerable
    # This modules handles class methods for {Headerable headerable classes}.
    module ClassMethods
      # Give protocol name for this class
      # @return [String]
      def protocol_name
        return @protocol_name if defined? @protocol_name

        classname = to_s
        @protocol_name = if classname.start_with?('PacketGen::Header')
                           classname.sub(/.*Header::/, '')
                         else
                           classname.sub(/.*::/, '')
                         end
      end
    end

    # @api private
    # Extend +klass+ with {ClassMethods}.
    # @param [Class] klass
    # @return [void]
    def self.included(klass)
      klass.extend(ClassMethods)
    end

    # Return header protocol name
    # @return [String]
    def protocol_name
      self.class.protocol_name
    end

    # return header method name
    # @return [String]
    def method_name
      return @method_name if defined? @method_name

      @method_name = protocol_name.downcase.gsub('::', '_')
    end

    # @abstract Should be redefined by subclasses. This method should check invariant
    #   attributes from header.
    # Called by {Packet#parse} when guessing first header to check if header is correct
    # @return [Boolean]
    def parse?
      true
    end

    # Reference on packet which owns this header
    # @return [Packet,nil]
    def packet
      @packet ||= nil
    end

    # @api private
    # Set packet to which this header belongs to
    # @param [Packet] packet
    # @return [Packet] packet
    def packet=(packet)
      @packet = packet
      added_to_packet(packet)
      @packet
    end

    # @abstract This base method does nothing but may be overriden by subclasses.
    # This method is called when a header is added to a packet.
    # @param [Packet] packet packet to which self is added
    # @return [void]
    def added_to_packet(packet) end

    # @abstract This method MUST be redefined by subclasses.
    # Populate headerable object from a binary string.
    # @param [String] str
    # @return [self]
    # @raise [NotImplementedError]
    def read(str)
      # Do not call super and rescue NoMethodError: too slow
      raise NotImplementedError, "#{self.class} should implement #read" if method(:read).super_method.nil?

      super
    end

    # @abstract This method MUST be redefined by subclasses.
    # Generate binary string from header
    # @return [String]
    # @raise [NotImplementedError]
    def to_s
      raise NotImplementedError, "#{self.class} should implement #to_s" if method(:to_s).super_method.nil?

      super
    end
  end
end
