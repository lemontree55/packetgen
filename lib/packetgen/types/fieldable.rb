# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types
    # Mixin to define minimal API for a class to be embbeded as a field in
    # {Fields} type.
    #
    # == Optional methods
    # These methods may, optionally, be defined by fieldable types:
    # * +from_human+ to load data from a human-readable string.
    # @author Sylvain Daubert
    # @since 3.1.6
    module Fieldable
      # Get type name
      # @return [String]
      def type_name
        self.class.to_s.split('::').last
      end

      # rubocop:disable Lint/UselessMethodDefinition
      # These methods are defined for documentation.

      # Populate object from a binary string
      # @param [String] str
      # @return [Fields] self
      # @abstract subclass should overload it.
      def read(str)
        super
      end

      # Return object as a binary string
      # @return [String]
      # @abstract subclass should overload it.
      def to_s
        super
      end

      # Size of object as binary string
      # @return [Integer]
      def sz
        to_s.size
      end

      # Return a human-readbale string
      # @return [String]
      # @abstract subclass should overload it.
      def to_human
        super
      end

      # rubocop:enable Lint/UselessMethodDefinition

      # Format object when inspecting a {Fields} object
      # @return [String]
      def format_inspect
        to_human
      end
    end
  end
end
