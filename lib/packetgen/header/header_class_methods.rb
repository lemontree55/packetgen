# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    module HeaderClassMethods

      # Simple class to handle header association
      Binding = Struct.new(:key, :value)

      # Bind a upper header to current class
      # @param [Class] header_klass header class to bind to current class
      # @param [Hash] args current class field and its value when +header_klass+
      #  is embedded in current class
      # @return [void]
      def bind_header(header_klass, args={})
        @known_headers ||= {}
        key = args.keys.first
        @known_headers[header_klass] = Binding.new(key, args[key])
      end

      # Get knwon headers
      # @return [Hash] keys: header classes, values: struct with methods #key and #value
      def known_headers
        @known_headers ||= {}
      end

      # Define a bitfield on given attribute
      #   class MyHeader < Struct.new(:flags)
      #   
      #     def initialize(options={})
      #       super Int16.new(options[:flags])
      #     end
      #     
      #     # define a bit field on :flag attribute:
      #     # flag1, flag2 and flag3 are 1-bit fields
      #     # type and stype are 3-bit fields. reserved is a 6-bit field
      #     define_bit_fields_on :flags, :flag1, :flag2, :flag3, :type, 3, :stype, 3, :reserved: 6
      #   end
      # A bitfield of size 1 bit defines 2 methods:
      # * +#field?+ which returns a Boolean,
      # * +#field=+ which takes and returns a Boolean.
      # A bitfield of more bits defines 2 methods:
      # * +#field+ which returns an Integer,
      # * +#field=+ which takes and returns an Integer.
      # @param [Symbol] attr attribute name (attribute should a {StructFu::Int}
      #   subclass)
      # @param [Array] args list of bitfield names. Name may be followed
      #   by bitfield size. If no size is given, 1 bit is assumed.
      # @return [void]
      def define_bit_fields_on(attr, *args)
        total_size = self.new[attr].width * 8
        idx = total_size - 1

        field = args.shift
        while field
          next unless field.is_a? Symbol
          size = if args.first.is_a? Integer
                   args.shift
                 else
                   1
                 end
          shift = idx - (size - 1)
          field_mask = (2**size - 1) << shift
          clear_mask = (2**total_size - 1) & (~field_mask & (2**total_size - 1))

          if size == 1
            class_eval <<-EOM
            def #{field}?
              val = (self[:#{attr}].to_i & #{field_mask}) >> #{shift}
              val != 0
            end
            def #{field}=(v)
              val = v ? 1 : 0
              self[:#{attr}].value = self[:#{attr}].to_i & #{clear_mask}
              self[:#{attr}].value |= val << #{shift}
            end
            EOM
          else
            class_eval <<-EOM
            def #{field}
              (self[:#{attr}].to_i & #{field_mask}) >> #{shift}
            end
            def #{field}=(v)
              self[:#{attr}].value = self[:#{attr}].to_i & #{clear_mask}
              self[:#{attr}].value |= (v & #{2**size - 1}) << #{shift}
            end
            EOM
          end

          idx -= size
          field = args.shift
        end
      end
    end
  end
end
