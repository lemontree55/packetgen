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
      include Inspectable

      class <<self
        # @return [Hash]
        attr_accessor :aliases
        attr_accessor :header_in_length
      end
      self.aliases = {}

      # Generate a TLV class
      # @param [Class] type_class Class to use for +type+
      # @param [Class] length_class Class to use for +length+
      # @param [Class] value_class Class to use for +value+
      # @param [Boolean] header_in_length if +true +, +type+ and +length+ fields are
      #   included in length
      # @return [Class]
      # @since 3.1.4 Add +header_in_length+ parameter
      def self.create(type_class: Int8Enum, length_class: Int8, value_class: String,
                      aliases: {}, header_in_length: false)
        raise Error, '.create cannot be called on a subclass of PacketGen::Types::AbstractTLV' unless self.equal? AbstractTLV

        klass = Class.new(self)
        klass.aliases = aliases
        klass.header_in_length = header_in_length

        if type_class < Enum
          klass.define_field :type, type_class, enum: {}
        else
          klass.define_field :type, type_class
        end
        klass.define_field :length, length_class
        klass.define_field :value, value_class

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
      def self.define_type_enum(hsh)
        field_defs[:type][:enum].clear
        field_defs[:type][:enum].merge!(hsh)
      end

      # @abstract Should only be called on real TLV classes, created by {.create}.
      # @param [Hash] options
      # @option options [Integer] :type
      # @option options [Integer] :length
      # @option options [Object] :value
      def initialize(options={})
        @header_in_length = self.class.header_in_length
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
        self[:type].read str[idx, self[:type].sz]
        idx += self[:type].sz
        self[:length].read str[idx, self[:length].sz]
        idx += self[:length].sz
        self[:value].read str[idx, real_length]
        self
      end

      # @abstract Should only be called on real TLV class instances.
      # Set +value+. May set +length+ if value is a {Types::String}.
      # @param [::String,Integer] val
      # @return [::String,Integer]
      def value=(val)
        self[:value].from_human val
        self.length = self[:value].sz
        self.length += self[:type].sz + self[:length].sz if @header_in_length
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
        "type:%s,length:%u,value:%s" % [human_type, length, my_value]
      end
      alias format_inspect to_human

      private

      def real_length
        if @header_in_length
          self.length - self[:type].sz - self[:length].sz
        else
          self.length
        end
      end
    end
  end
end
