# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

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
          addr = Addr.new.from_human(addr) unless addr.is_a?(Addr)
          super(addr)
        end
      end

      # Base class for IP options
      # @author Sylvain Daubert
      class Option < Types::Fields
        include Types::Fieldable

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

            optname = cst.to_s.sub('_TYPE', '')
            @types[optname] = Option.const_get(cst)
          end
          @types
        end

        # Factory to build an option from its type
        # @return [Option]
        def self.build(options={})
          type = options[:type]
          klass = case type
                  when String
                    types.key?(type) ? IP.const_get(type) : self
                  else
                    types.value?(type) ? IP.const_get(types.key(type.to_i)) : self
                  end
          options.delete(:type) if klass != self
          klass.new(options)
        end

        def initialize(options={})
          options[:type] = class2type unless options[:type]

          super
          initialize_length_if_needed(options)
          initialize_data_if_needed(options)
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
          str = self.instance_of?(Option) ? +"unk-#{type}" : self.class.to_s.sub(/.*::/, '')
          str << ":#{self[:data].to_s.inspect}" if respond_to?(:length) && (length > 2) && !self[:data].to_s.empty?
          str
        end

        private

        def class2type
          opt_name = self.class.to_s.gsub(/.*::/, '')
          Option.const_get(:"#{opt_name}_TYPE") if Option.const_defined? :"#{opt_name}_TYPE"
        end

        def initialize_length_if_needed(options)
          self.length = sz if respond_to?(:length) && options[:length].nil?
        end

        def initialize_data_if_needed(options)
          return unless fields.include?(:data) && self[:data].respond_to?(:from_human) && options.key?(:data)

          # Force data if data is set in options but not length
          self.length += options[:data].size
          self[:data].from_human(options[:data])
        end
      end

      # End-of-option-List IP option
      class EOL < Option
        remove_field :length
        remove_field :data
      end

      # No OPeration IP option
      class NOP < EOL; end

      # Loose Source and Record Route IP option
      class LSRR < Option
        remove_field :data

        # @!attribute pointer
        #  8-bit pointer on next address
        #  @return [Integer]
        define_field :pointer, Types::Int8, default: 4
        # @!attribute data
        #  Array of IP addresses
        #  @return [Types::Array<IP::Addr>]
        define_field :data, ArrayOfAddr, builder: ->(h, t) { t.new(length_from: -> { h.length - 3 }) }

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
        remove_field :data

        # @!attribute id
        #  16-bit stream ID
        #  @return [Integer]
        define_field :id, Types::Int16

        def to_human
          super << ":#{self.id}"
        end
      end

      # Router Alert IP option
      class RA < Option
        remove_field :data

        # @!attribute value
        #  16-bit value. Should be 0.
        #  @return [Integer]
        define_field :value, Types::Int16, default: 0

        def to_human
          super << ":#{self.value}"
        end
      end
    end
  end
end
