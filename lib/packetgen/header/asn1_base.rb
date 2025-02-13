# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

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

      class << self
        # Define some methods from given ASN.1 attributes to mimic {Base} attributes
        # @param [Array<Symbol>] attributes
        # @return [void]
        def define_attributes(*attributes)
          @attributes = attributes
          attributes.each do |attr|
            class_eval "def #{attr}; @elements[:#{attr}].value; end\n" \
                       "def #{attr}=(v); @elements[:#{attr}].value = v; end"
          end
        end

        def known_headers
          @known_headers ||= {}.freeze
        end
      end

      alias parse parse!
      alias to_s to_der

      # Read a BER string
      # @param [String] str
      # @return [ASN1Base] self
      def read(str)
        begin
          parse(str, ber: true)
        rescue RASN1::ASN1Error
          # suppress exception to allow guessing
        end
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
