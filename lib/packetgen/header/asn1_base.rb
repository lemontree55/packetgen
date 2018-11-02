# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

require 'rasn1'

module PacketGen
  module Header
    # @abstract Base class for ASN.1 header types.
    #    This class implement minimal {Base} API to mimic a {Base} object.
    #
    #    Subclasses may define magic methods:
    #    * {#parse?}.
    # @author Sylvain Daubert
    # @since 2.0.0
    class ASN1Base < RASN1::Model
      include Headerable

      # Define some methods from given ASN.1 fields to mimic {Base} attributes
      # @param [Array<Symbol>] attributes
      # @return [void]
      def self.define_attributes(*attributes)
        @attributes = attributes
        attributes.each do |attr|
          class_eval "def #{attr}; @elements[:#{attr}].value; end\n" \
                     "def #{attr}=(v); @elements[:#{attr}].value = v; end"
        end
      end

      alias parse parse!
      alias to_s to_der

      # Read a BER string
      # @param [String] str
      # @return [ASN1Base] self
      def read(str)
        parse(str, ber: true)
        self
      end

      # Common inspect method for ASN.1 headers
      # @return [String]
      def inspect
        str = Inspect.dashed_line(self.class, 1)
        self.class.class_eval { @attributes }.each do |attr|
          str << Inspect.inspect_asn1_attribute(attr, self[attr], 1)
        end
        str
      end
    end
  end
end
