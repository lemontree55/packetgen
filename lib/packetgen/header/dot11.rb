# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.
require 'zlib'

module PacketGen
  module Header

    # PPI (Per-Packet Information) packet
    #@author Sylvain Daubert
    class PPI < Base
      # @!attribute version
      #  @return [Integer] 8-bit PPI version
      define_field :version, Types::Int8, default: 0
      # @!attribute flags
      #  @return [Integer] 8-bit PPI flags
      define_field :flags, Types::Int8
      # @!attribute length
      #  @return [Integer] 16-bit PPI header length
      define_field :length, Types::Int16le, default: 8
      # @!attribute dlt
      #  @return [Integer] 32-bit PPI data link type
      define_field :dlt, Types::Int32le
      # @!attribute ppi_fields
      #  @return [Type::String] concatenation of PPI fields
      define_field :ppi_fields, Types::String
      # @!attribute body
      #  @return [Type::String]
      define_field :body, Types::String
      # @!attribute align
      #  @return [Boolean] align flag from {#flags} attribute
      define_bit_fields_on :flags, :reserved, 7, :align

      # @param [String] str
      # @return [PPI] self
      def read(str)
        return self if str.nil?
        force_binary str
        self[:version].read str[0, 1]
        self[:flags].read str[1, 1]
        self[:length].read str[2, 2]
        self[:dlt].read str[4, 4]
        self[:ppi_fields].read str[8, length - 8]
        self[:body].read str[length, str.size]
        self
      end

      # Check version field
      # @see [Base#parse?]
      def parse?
        version == 0
      end

      # send PPI packet on wire. Dot11 FCS trailer should be set.
      # @param [String] iface interface name
      # @return [void]
      def to_w(iface)
        pcap = PCAPRUB::Pcap.open_live(iface, PCAP_SNAPLEN, PCAP_PROMISC,
                                       PCAP_TIMEOUT)
        pcap.inject self.to_s
      end
    end
    self.add_class PPI

    # Radiotap header
    # @author Sylvain Daubert
    class RadioTap < Base
      # @!attribute version
      #  @return [Integer] 8-bit version
      define_field :version, Types::Int8, default: 0
      # @!attribute pad
      #  @return [Integer] 8-bit pad
      define_field :pad, Types::Int8, default: 0
      # @!attribute length
      #  @return [Integer] 16-bit RadioTap header length
      define_field :length, Types::Int16le
      # @!attribute present_flags
      #  @return [Integer] 32-bit integer
      define_field :present_flags, Types::Int32le
      # @!attribute radio_fields
      #  @return [Type::String] concatenation of RadioTap fields
      define_field :radio_fields, Types::String
      # @!attribute body
      #  @return [Type::String]
      define_field :body, Types::String

      # @param [String] str
      # @return [RadioTap] self
      def read(str)
        return self if str.nil?
        force_binary str
        self[:version].read str[0, 1]
        self[:pad].read str[1, 1]
        self[:length].read str[2, 2]
        self[:present_flags].read str[4, 4]
        self[:radio_fields].read str[8, length - 8]
        self[:body].read str[length, str.size]
        self
      end

      # Check version field
      # @see [Base#parse?]
      def parse?
        version == 0
      end

      # send RadioTap packet on wire. Dot11 FCS trailer should be set.
      # @param [String] iface interface name
      # @return [void]
      def to_w(iface)
        pcap = PCAPRUB::Pcap.open_live(iface, PCAP_SNAPLEN, PCAP_PROMISC,
                                       PCAP_TIMEOUT)
        pcap.inject self.to_s
      end
    end
    self.add_class RadioTap

    # IEEE 802.11 header
    # @abstract This is a base class to demultiplex different IEEE 802.11 frames when
    #   parsing.
    # A IEEE 802.11 header may consists of at least:
    # * a {#frame_ctrl} ({Types::Int16}),
    # * a {#id}/duration ({Types::Int16le}),
    # * and a {#mac1} ({Eth::MacAddr}).
    # Depending on frame type and subtype, it may also contains:
    # * a {#mac2} ({Eth::MacAddr}),
    # * a {#mac3} ({Eth::MacAddr}),
    # * a {#sequence_ctrl} ({Types::Int16}),
    # * a {#mac4} ({Eth::MacAddr}),
    # * a {#qos_ctrl} ({Types::Int16}),
    # * a {#ht_ctrl} ({Types::Int32}),
    # * a {#body} (a {Types::String} or another {Base} class),
    # * a Frame check sequence ({#fcs}, of type {Types::Int32le})
    #
    # == header accessors
    # As Dot11 header types are defined under Dot11 namespace, Dot11 header accessors
    # have a specific name. By example, to access to a {Dot11::Beacon} header,
    # accessor is +#dot11_beacon+.
    # @author Sylvain Daubert
    class Dot11 < Base

      # Frame types
      TYPES = %w(Management Control Data Reserved).freeze

      class << self
        # Set a flag for parsing Dot11 packets. If set to +true+, parse FCS field,
        # else don't. Default is +true+.
        # @return [Boolean]
        attr_accessor :has_fcs
      end
      Dot11.has_fcs = true

      # @!attribute frame_ctrl
      #  @return [Integer] 16-bit frame control word
      define_field :frame_ctrl, Types::Int16, default: 0
      # @!attribute id
      #  @return [Integer] 16-bit ID/Duration word
      define_field :id, Types::Int16le, default: 0
      # @!attribute mac1
      #  @return [Eth::MacAddr]
      define_field :mac1, Eth::MacAddr
      # @!attribute mac2
      #  @return [Eth::MacAddr]
      define_field :mac2, Eth::MacAddr
      # @!attribute mac3
      #  @return [Eth::MacAddr]
      define_field :mac3, Eth::MacAddr
      # @!attribute sequence_ctrl
      #  @return [Integer] 16-bit sequence control word
      define_field :sequence_ctrl, Types::Int16le, default: 0
      # @!attribute mac4
      #  @return [Eth::MacAddr]
      define_field :mac4, Eth::MacAddr
      # @!attribute qos_ctrl
      #  @return [Integer] 16-bit QoS control word
      define_field :qos_ctrl, Types::Int16
      # @!attribute ht_ctrl
      #  @return [Integer] 16-bit HT control word
      define_field :ht_ctrl, Types::Int32
      # @!attribute body
      #  @return [Types::String]
      define_field :body, Types::String
      # @!attribute fcs
      #  @return [Types::Int32le]
      define_field :fcs, Types::Int32le

      # @!attribute subtype
      #  @return [Integer] 4-bit frame subtype from {#frame_ctrl}
      # @!attribute type
      #  @return [Integer] 2-bit frame type from {#frame_ctrl}
      # @!attribute proto_version
      #  @return [Integer] 2-bit protocol version from {#frame_ctrl}
      # @!attribute order
      #  @return [Boolean] order flag from {#frame_ctrl}
      # @!attribute wep
      #  @return [Boolean] wep flag from {#frame_ctrl}
      # @!attribute md
      #  @return [Boolean] md flag from {#frame_ctrl}
      # @!attribute pwmngt
      #  @return [Boolean] pwmngt flag from {#frame_ctrl}
      # @!attribute retry
      #  @return [Boolean] retry flag from {#frame_ctrl}
      # @!attribute mf
      #  @return [Boolean] mf flag from {#frame_ctrl}
      # @!attribute from_ds
      #  @return [Boolean] from_ds flag from {#frame_ctrl}
      # @!attribute to_ds
      #  @return [Boolean] to_ds flag from {#frame_ctrl}
      define_bit_fields_on :frame_ctrl,  :subtype, 4, :type, 2, :proto_version, 2,
                            :order, :wep, :md, :pwmngt, :retry, :mf, :from_ds, :to_ds

      alias duration id
      # @private
      alias old_fields fields

      # @param [Hash] options
      # @see Base#initialize
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
      alias old_read read

      # Populate object from a binary string
      # @param [String] str
      # @return [Dot11] may return a subclass object if a more specific class
      #   may be determined
      def read(str)
        has_fcs = Dot11.has_fcs

        if self.class == Dot11
          return self if str.nil?
          force_binary str
          self[:frame_ctrl].read str[0, 2]

          case type
          when 0
            Dot11::Management.new.read str
          when 1
            Dot11::Control.new.read str
          when 2
            Dot11::Data.new.read str
          else
            private_read str, has_fcs
          end
        else
          private_read str, has_fcs
        end
      end

      # Compute checksum and set +fcs+ field
      # @return [Integer]
      def calc_checksum
        fcs = Zlib.crc32(to_s[0...-4])
        self.fcs = fcs
        fcs
      end

      # @return [String]
      def to_s
        define_applicable_fields
        @applicable_fields.map { |f| force_binary @fields[f].to_s }.join
      end

      # Get human readable type
      # @return [String]
      def human_type
        TYPES[type]
      end

      # @return [String]
      def inspect
        str = if self.class == Dot11
                Inspect.dashed_line("#{self.class} #{human_type}", 2)
              elsif self.respond_to? :human_subtype
                Inspect.dashed_line("#{self.class} #{human_subtype}", 2)
              else
                Inspect.dashed_line("#{self.class}", 2)
              end
        define_applicable_fields
        @applicable_fields.each do |attr|
          next if attr == :body
          str << Inspect.inspect_attribute(attr, @fields[attr], 2)
        end
        str
      end

      # send Dot11 packet on wire.
      # @param [String] iface interface name
      # @return [void]
      def to_w(iface)
        pcap = PCAPRUB::Pcap.open_live(iface, PCAP_SNAPLEN, PCAP_PROMISC,
                                       PCAP_TIMEOUT)
        str = self.to_s
        pcap.inject str << [crc32].pack('V')
      end

      private

      def define_applicable_fields
        if to_ds? and from_ds?
          @applicable_fields[6, 0] = :mac4 unless @applicable_fields.include? :mac4
        else
          @applicable_fields -= %i(mac4)
        end
        if order?
          unless @applicable_fields.include? :ht_ctrl
            idx = @applicable_fields.index(:body)
            @applicable_fields[idx, 0] = :ht_ctrl
          end
        else
          @applicable_fields -= %i(ht_ctrl)
        end
        if Dot11.has_fcs
          @applicable_fields << :fcs unless @applicable_fields.include? :fcs
        else
          @applicable_fields -= %i(fcs)
        end
      end

      def private_read(str, has_fcs)
        self[:frame_ctrl].read str[0, 2]
        define_applicable_fields
        if has_fcs
          old_read str[0...-4]
          self[:fcs].read str[-4..-1]
        else
          old_read str
        end
        self
      end
    end

    self.add_class Dot11
    PPI.bind_header Dot11, dlt: PcapNG::LINKTYPE_IEEE802_11
    RadioTap.bind_header Dot11
  end
end

require_relative 'dot11/element'
require_relative 'dot11/management'
require_relative 'dot11/sub_mngt'
require_relative 'dot11/control'
require_relative 'dot11/data'
