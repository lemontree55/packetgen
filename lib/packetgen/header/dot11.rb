# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    # PPI (Per-Packet Infoamtion) packet
    #@author Sylvain Daubert
    class PPI < Base
      define_field :version, Types::Int8, default: 0
      define_field :flags, Types::Int8
      define_field :length, Types::Int16le, default: 8
      define_field :dlt, Types::Int32le
      define_field :ppi_fields, Types::String,
                   builder: ->(ppi) { Types::String.new('', length_from: ppi[:length]) }
      define_field :body, Types::String

      define_bit_fields_on :flags, :reserved, 7, :align
    end
    self.add_class PPI

    # IEEE 802.11 header
    # @author Sylvain Daubert
    class Dot11 < Base

      # Frame types
      TYPES = %w(Management Control Data Reserved)

      define_field :frame_control, Types::Int16, default: 0
      define_field :id, Types::Int16, default: 0
      define_field :mac1, Eth::MacAddr
      define_field :mac2, Eth::MacAddr
      define_field :mac3, Eth::MacAddr
      define_field :sequence_control, Types::Int16, default: 0
      define_field :mac4, Eth::MacAddr
      define_field :qos_control, Types::Int16
      define_field :ht_control, Types::Int32
      define_field :body, Types::String

      define_bit_fields_on :frame_control,  :subtype, 4, :type, 2, :proto_version, 2,
                           :to_ds, :from_ds, :mf, :retry, :pwmngt, :md, :wep, :order

      # @private
      alias old_fields fields
      
      def initialize(options={})
        super
        @applicable_fields = old_fields
      end

      # Get all used field names
      # @return [Array<Symbol>]
      def fields
        @applicable_fields
      end

      # @private
      alias private_read read

      # Populate object from a binary string
      # @param [String] str
      # @return [Dot11] may return a subclass object if a more specific class
      #   may be determined
      def read(str)
        return self if str.nil?
        force_binary str
        self[:frame_control].read str[0, 2]
        case type
        when 0
          Dot11::Management.new.read str
        when 1
          Dot11::Control.new.read str
        else
          private_read str
        end
      end

      def to_s
        @applicable_fields.map { |f| force_binary @fields[f].to_s }.join
      end

      def human_type
        TYPES[type]
      end

      def inspect
        str = if self.class == Dot11
                Inspect.dashed_line("#{self.class} #{human_type}", 2)
              elsif self.respond_to? :human_subtype
                Inspect.dashed_line("#{self.class} #{human_subtype}", 2)
              else
                Inspect.dashed_line("#{self.class}", 2)
              end
        @applicable_fields.each do |attr|
          next if attr == :body
          str << Inspect.inspect_attribute(attr, @fields[attr], 2)
        end
        str
      end
    end

    self.add_class Dot11
    PPI.bind_header Dot11, dlt: PcapNG::LINKTYPE_IEEE802_11
  end
end

require_relative 'dot11/element'
require_relative 'dot11/management'
require_relative 'dot11/sub_mngt'
require_relative 'dot11/control'
