# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types
    # Class to handle Type-Length-Value attributes
    #
    # TLV fields handles three subfields:
    # * a tag/type field (defaults: {Int8} type),
    # * a length field (defaults: {Int8} type),
    # * a value field (defaults: {String} type).
    #
    # {#initialize} supports options to change tag and length type. By example, to
    # declare a TLV using {Int16}:
    #    define_field :tlv, PacketGen::Types::TLV, builder: ->(obj) { PacketGen::Types::TLV.new(t: PacketGen::Types::Int16, l: PacketGen::Types::Int16) }
    #
    # == Subclasses
    # A subclass may defined a constant hash TYPES. This hash defines human readable
    # types versus their integer values. Hash keys are integer values, and hash values
    # are types as strings.
    #
    # If TYPES is defined, a subclass may:
    # * print human readable type using {#human_type},
    # * set type as String with {#type=}.
    # @author Sylvain Daubert
    # @deprecated Use {AbstractTLV} instead.
    # @since 3.1.0 deprecated
    class TLV < Fields
      # @!attribute type
      #  @return [Integer]
      define_field :type, Int8
      # @!attribute length
      #  @return [Integer]
      define_field :length, Int8
      # @!attribute value
      #  @return [String]
      define_field :value, String

      # @param [Hash] options
      # @option options [Integer] :type
      # @option options [Integer] :length
      # @option options [String] :value
      # @option options [Class] :t {Int} subclass for +:type+ attribute.
      #   Default: {Int8}.
      # @option options [Class] :l {Int} subclass for +:length+ attribute.
      #   Default: {Int8}.
      # @option options [Class] :v {String} subclass for +:value+ attribute.
      #   Default: {Types::String}.
      def initialize(options={})
        Deprecation.deprecated_class(self.class, AbstractTLV)
        super
        self[:type] = options[:t].new(self.type) if options[:t]
        self[:length] = options[:l].new(self.length) if options[:l]
        self[:value] = options[:v].new if options[:v]
        self.type = options[:type] if options[:type]
        self.value = options[:value] if options[:value]
        self.length = options[:length] if options[:length]
      end

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

      # @private
      alias old_type= type=

      undef type=, value=, value

      # Set type
      # @param [::String,Integer] val
      # @return [Integer]
      # @raise [TypeError] class does not define TYPES
      # @raise [ArgumentError] unknown string type
      def type=(val)
        case val
        when Integer
          self.old_type = val
        else
          raise TypeError, 'need an Integer' unless human_types?

          new_val = self.class::TYPES.key(val.to_s)
          raise ArgumentError, "unknown #{val} type" if new_val.nil?

          self.old_type = new_val
        end
      end

      # Set +value+. May set +length+ if value is a {Types::String}.
      # @param [::String,Integer] val
      # @return [::String,Integer]
      def value=(val)
        self[:value].from_human val
        self.length = self[:value].sz
        val
      end

      # Get +value+
      # @return [Object] depend on +value+ type
      def value
        self[:value].to_human
      end

      # Return human readable type, if TYPES is defined
      # @return [String]
      def human_type
        if human_types?
          htype = self.class::TYPES[type]
          htype = type if htype.nil?
          htype.to_s
        else
          type.to_s
        end
      end

      # @return [String]
      def to_human
        name = self.class.to_s.gsub(/.*::/, '')
        @typestr ||= if human_types?
                       types = self.class::TYPES.values
                       "%-#{types.max_by(&:length).size}s"
                     else
                       '%s'
                     end
        @lenstr ||= "%-#{(2**(self[:length].width * 8) - 1).to_s.size}u"
        "#{name} type:#{@typestr} length:#{@lenstr} value:#{value.inspect}" % [human_type,
                                                                               length]
      end

      private

      def human_types?
        self.class.const_defined? :TYPES
      end
    end
  end
end
