# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Types
    # This class is an abstract class to define type-length-value data.
    #
    # This class supersede {TLV} class, which is not well defined on some corner
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
    # Each field's type may be change at generating TLV class:
    #   MyTLV = PacketGen::Types::AbstractTLV.create(type_class: PacketGen::Types::Int16,
    #                                                length_class: PacketGen::Types::Int16,
    #                                                value_class: PacketGen::Header::IP::Addr)
    #   tlv = MyTLV.new(type: 1, value: '1.2.3.4')
    #   tlv.type        #=> 1
    #   tlv.length      #=> 4
    #   tlv.value       #=> 42
    #   tlv.to_s        #=> "\x00\x01\x00\x04\x01\x02\x03\x04"
    # @author Sylvain Daubert
    class AbstractTLV < Types::Fields
      # Generate a TLV class
      # @param [Class] type_class Class to use for +type+
      # @param [Class] length_class Class to use for +length+
      # @param [Class] value_class Class to use for +value+
      # @return [Class]
      def self.create(type_class: Int8Enum, length_class: Int8, value_class: String)
        raise Error, '.create cannot be called on a subclass of PacketGen::Types::AbstractTLV' unless self.equal? AbstractTLV

        klass = Class.new(self)

        if type_class < Enum
          klass.define_field :type, type_class, enum: {}
        else
          klass.define_field :type, type_class
        end
        klass.define_field :length, length_class
        klass.define_field :value, value_class

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
        self[:value].read str[idx, self.length]
        self
      end

      # @abstract Should only be called on real TLV class instances.
      # Set +value+. May set +length+ if value is a {Types::String}.
      # @param [::String,Integer] val
      # @return [::String,Integer]
      def value=(val)
        self[:value].from_human val
        self.length = self[:value].sz
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
        name = self.class.to_s.gsub(/.*::/, '')
        @typestr ||= if self[:type].respond_to? :enum
                       "%-#{self[:type].enum.keys.max_by(&:length).size}s"
                     else
                       '%s'
                     end
        @lenstr ||= "%-#{(2**(self[:length].width * 8) - 1).to_s.size}u"
        "#{name} type:#{@typestr} length:#{@lenstr} value:#{value.inspect}" % [human_type, length]
      end
    end
  end
end
