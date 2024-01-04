# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types
    # This class is an abstract class to define type-length-value data.
    #
    # This class supersedes {TLV} class, which is not well defined on some corner
    # cases.
    #
    # ===Usage
    # To simply define a new TLV class, do:
    #   MyTLV = PacketGen::Types::AbstractTLV.create
    #   MyTLV.define_type_enum 'one' => 1, 'two' => 2
    # This will define a new +MyTLV+ class, subclass of {Fields}. This class will
    # define 3 fields:
    # * +#type+, as a {Int8Enum} by default,
    # * +#length+, as a {Int8} by default,
    # * and +#value+, as a {String} by default.
    # +.define_type_enum+ is, here, necessary to define enum hash to be used
    # for +#type+ accessor, as this one is defined as an {Enum}.
    #
    # This class may then be used as older {TLV} class:
    #   tlv = MyTLV.new(type: 1, value: 'abcd')  # automagically set #length from value
    #   tlv.type        #=> 1
    #   tlv.human_type  #=> 'one'
    #   tlv.length      #=> 4
    #   tlv.value       #=> "abcd"
    #
    # ===Advanced usage
    # Each field's type may be changed at generating TLV class:
    #   MyTLV = PacketGen::Types::AbstractTLV.create(type_class: PacketGen::Types::Int16,
    #                                                length_class: PacketGen::Types::Int16,
    #                                                value_class: PacketGen::Header::IP::Addr)
    #   tlv = MyTLV.new(type: 1, value: '1.2.3.4')
    #   tlv.type        #=> 1
    #   tlv.length      #=> 4
    #   tlv.value       #=> '1.2.3.4'
    #   tlv.to_s        #=> "\x00\x01\x00\x04\x01\x02\x03\x04"
    #
    # Some aliases may also be defined. For example, to create a TLV type
    # whose +type+ field should be named +code+:
    #   MyTLV = PacketGen::Types::AbstractTLV.create(type_class: PacketGen::Types::Int16,
    #                                                length_class: PacketGen::Types::Int16,
    #                                                aliases: { code: :type })
    #   tlv = MyTLV.new(code: 1, value: 'abcd')
    #   tlv.code        #=> 1
    #   tlv.type        #=> 1
    #   tlv.length      #=> 4
    #   tlv.value       #=> 'abcd'
    #
    # @author Sylvain Daubert
    # @since 3.1.0
    # @since 3.1.1 add +:aliases+ keyword to {#initialize}
    class AbstractTLV < Types::Fields
      include Fieldable

      # @private
      FIELD_TYPES = { 'T' => :type, 'L' => :length, 'V' => :value }.freeze

      class << self
        # @return [Hash]
        attr_accessor :aliases
        # @deprecated
        attr_accessor :header_in_length
        # @private
        attr_accessor :field_in_length

        # Generate a TLV class
        # @param [Class] type_class Class to use for +type+
        # @param [Class] length_class Class to use for +length+
        # @param [Class] value_class Class to use for +value+
        # @param [Boolean] header_in_length if +true +, +type+ and +length+ fields are
        #   included in length. Deprecated, use +field_in_length+ instead.
        # @param [String] field_order give field order. Each character in [T,L,V] MUST be present once, in the desired order.
        # @param [String] field_in_length give fields to compute length on.
        # @return [Class]
        # @since 3.1.4 Add +header_in_length+ parameter
        # @since 3.3.1 Add +field_order+ and +field_in_length' parameters. Deprecate +header_in_length+ parameter.
        def create(type_class: Int8Enum, length_class: Int8, value_class: String,
                   aliases: {}, header_in_length: false, field_order: 'TLV', field_in_length: 'V')
          Deprecation.deprecated_option(self, 'create', 'header_in_length', klass_method: true) if header_in_length
          raise Error, '.create cannot be called on a subclass of PacketGen::Types::AbstractTLV' unless self.equal?(AbstractTLV)

          klass = Class.new(self)
          klass.aliases = aliases
          klass.header_in_length = header_in_length
          klass.field_in_length = field_in_length

          check_field_in_length(field_in_length)
          check_field_order(field_order)
          generate_fields(klass, field_order, type_class, length_class, value_class)

          aliases.each do |al, orig|
            klass.instance_eval do
              alias_method al, orig if klass.method_defined?(orig)
              alias_method :"#{al}=", :"#{orig}=" if klass.method_defined?(:"#{orig}=")
            end
          end

          klass
        end

        # @!attribute type
        #   @abstract Type attribute for real TLV class
        #   @return [Integer]
        # @!attribute length
        #   @abstract Length attribute for real TLV class
        #   @return [Integer]
        # @!attribute value
        #   @abstract Value attribute for real TLV class
        #   @return [Object]

        # @abstract Should only be called on real TLV classes, created by {.create}.
        # Set enum hash for {#type} field.
        # @param [Hash] hsh enum hash
        # @return [void]
        def define_type_enum(hsh)
          field_defs[:type][:enum].clear
          field_defs[:type][:enum].merge!(hsh)
        end

        private

        def check_field_in_length(field_in_length)
          return if /^[TLV]{1,3}$/.match?(field_in_length)

          raise 'field_in_length must only contain T, L and/or V characters'
        end

        def check_field_order(field_order)
          return if field_order.match(/^[TLV]{3,3}$/) && (field_order[0] != field_order[1]) && (field_order[0] != field_order[2]) && (field_order[1] != field_order[2])

          raise 'field_order must contain all three letters TLV, each once'
        end

        def generate_fields(klass, field_order, type_class, length_class, value_class)
          field_order.each_char do |field_type|
            case field_type
            when 'T'
              if type_class < Enum
                klass.define_field(:type, type_class, enum: {})
              else
                klass.define_field(:type, type_class)
              end
            when 'L'
              klass.define_field(:length, length_class)
            when 'V'
              klass.define_field(:value, value_class)
            end
          end
        end
      end

      # @abstract Should only be called on real TLV classes, created by {.create}.
      # @param [Hash] options
      # @option options [Integer] :type
      # @option options [Integer] :length
      # @option options [Object] :value
      def initialize(options={})
        @header_in_length = self.class.header_in_length
        @field_in_length = self.class.field_in_length
        self.class.aliases.each do |al, orig|
          options[orig] = options[al] if options.key?(al)
        end

        super
        # used #value= defined below, which set length if needed
        self.value = options[:value] if options[:value]
      end

      # @abstract Should only be called on real TLV class instances.
      # Populate object from a binary string
      # @param [String] str
      # @return [Fields] self
      def read(str)
        idx = 0
        fields.each do |field_name|
          field = self[field_name]
          length = field_name == :value ? real_length : field.sz
          field.read(str[idx, length])
          idx += field.sz
        end

        self
      end

      # @abstract Should only be called on real TLV class instances.
      # Set +value+. May set +length+ if value is a {Types::String}.
      # @param [::String,Integer] val
      # @return [::String,Integer]
      def value=(val)
        self[:value].from_human(val)

        fil = @field_in_length
        fil = 'TLV' if @header_in_length

        length = 0
        fil.each_char do |field_type|
          length += self[FIELD_TYPES[field_type]].sz
        end
        self.length = length

        val
      end

      # @abstract Should only be called on real TLV class instances.
      # Get human-readable type
      # @return [String]
      def human_type
        self[:type].to_human.to_s
      end

      # @abstract Should only be called on real TLV class instances.
      # @return [String]
      def to_human
        my_value = self[:value].is_a?(String) ? self[:value].inspect : self[:value].to_human
        'type:%s,length:%u,value:%s' % [human_type, length, my_value]
      end

      private

      def real_length
        if @header_in_length
          self.length - self[:type].sz - self[:length].sz
        else
          length = self.length
          length -= self[:type].sz if @field_in_length.include?('T')
          length -= self[:length].sz if @field_in_length.include?('L')
          length
        end
      end
    end
  end
end
