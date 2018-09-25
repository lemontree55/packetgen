# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class IP
      # Class to handle series of IP addresses
      # @author Sylvain Daubert
      class ArrayOfAddr < Types::Array
        set_of IP::Addr

        # Push a IP address to the array
        # @param [String,Addr] addr
        # @return [self]
        #   array << '192.168.1.12'
        def push(addr)
          addr = addr.is_a?(Addr) ? addr : Addr.new.from_human(addr)
          super(addr)
        end
      end

      # Base class for IP options
      # @author Sylvain Daubert
      class Option < Types::Fields
        # EOL option type
        EOL_TYPE = 0x00
        # NOP option type
        NOP_TYPE = 0x01
        # LSRR option type
        LSRR_TYPE = 0x83
        # SSRR option type
        SSRR_TYPE = 0x84
        # RR option type
        RR_TYPE = 0x07
        # SI option type
        SI_TYPE = 0x88
        # RA option type
        RA_TYPE = 0x94

        # @!attribute type
        #  8-bit option type
        # @return [Integer]
        define_field :type, Types::Int8
        # @!attribute length
        #  8-bit option length. If 0, there is no +length+ field in option
        # @return [Integer]
        define_field :length, Types::Int8, default: 0, optional: ->(h) { h.type > 1 }
        # @!attribute data
        #  option data
        # @return [String]
        define_field :data, Types::String, optional: ->(h) { h.length > 2 },
                     builder: ->(h, t) { t.new(length_from: -> { h.length - 2 }) }

        # @!attribute copied
        #  1-bit copied flag from {#type} field
        #  @return [Boolean]
        # @!attribute option_class
        #  2-bit option class (0: control, 2: debug and measurement, 1 and 3:
        #  reserved) from {#type} field
        #  @return [Integer]
        # !@attribute number
        #  5-bit option number from {#type} field
        #  @return [Integer]
        define_bit_fields_on :type, :copied, :option_class, 2, :number, 5

        # @return [Hash]
        def self.types
          return @types if defined? @types
          @types = {}
          Option.constants.each do |cst|
            next unless cst.to_s.end_with? '_TYPE'
            optname = cst.to_s.sub(/_TYPE/, '')
            @types[Option.const_get(cst)] = IP.const_get(optname)
          end
          @types
        end

        def initialize(options={})
          unless options[:type]
            opt_name = self.class.to_s.gsub(/.*::/, '')
            if Option.const_defined? "#{opt_name}_TYPE"
              options[:type] = Option.const_get("#{opt_name}_TYPE")
            end
          end
          super
        end

        # Get binary string. Set {#length} field.
        # @return [String]
        def to_s
          self.length = super.size if respond_to? :length
          super
        end

        # Get a human readable string
        # @return [String]
        def to_human
          str = self.class == Option ? "unk-#{type}" : self.class.to_s.sub(/.*::/, '')
          if respond_to?(:length) && (length > 2) && !self[:data].to_s.empty?
            str << ":#{self[:data].to_s.inspect}"
          end
          str
        end
      end

      # End-of-option-List IP option
      class EOL < Option
        delete_field :length
        delete_field :data
      end

      # No OPeration IP option
      class NOP < EOL
      end

      # Loose Source and Record Route IP option
      class LSRR < Option
        delete_field :data

        # @!attribute pointer
        #  8-bit pointer on next address
        #  @return [Integer]
        define_field :pointer, Types::Int8
        # @!attribute data
        #  Array of IP addresses
        #  @return [Types::Array<IP::Addr>]
        define_field :data, ArrayOfAddr,
                     builder: ->(h, t) { t.new(length_from: -> { h.length - 2 }) }

        # Populate object from a binary string
        # @param [String] str
        # @return [Fields] self
        def read(str)
          return self if str.nil?
          force_binary str
          self[:type].read str[0, 1]
          self[:length].read str[1, 1]
          self[:pointer].read str[2, 1]
          self[:data].read str[3, length - 3]
          self
        end

        # Get IP address pointer by {#pointer}
        # @return [Addr]
        def pointed_addr
          data[pointer / 4 - 1]
        end

        # Get a human readable string
        # @return [String]
        def to_human
          str = self.class.to_s.sub(/.*::/, '')
          str << ':' << self[:data].to_human
        end
      end

      # Strict Source and Record Route IP option
      class SSRR < LSRR; end
      # Record Route IP option
      class RR < LSRR; end

      # Stream Identifier IP option
      class SI < Option
        delete_field :data

        # @!attribute id
        #  16-bit stream ID
        #  @return [Integer]
        define_field :id, Types::Int16
      end

      # Router Alert IP option
      class RA < Option
        delete_field :data

        # @!attribute value
        #  16-bit value. Should be 0.
        #  @return [Integer]
        define_field :value, Types::Int16, default: 0
      end
    end
  end
end
