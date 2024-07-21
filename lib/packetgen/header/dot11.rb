# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require 'zlib'

module PacketGen
  module Header
    # PPI (Per-Packet Information) packet
    # @author Sylvain Daubert
    # @since 1.4.0
    class PPI < Base
      # @!attribute version
      #  @return [Integer] 8-bit PPI version
      define_attr :version, BinStruct::Int8, default: 0
      # @!attribute flags
      #  @return [Integer] 8-bit PPI flags
      define_attr :flags, BinStruct::Int8
      # @!attribute length
      #  @return [Integer] 16-bit PPI header length
      define_attr :length, BinStruct::Int16le, default: 8
      # @!attribute dlt
      #  @return [Integer] 32-bit PPI data link type
      define_attr :dlt, BinStruct::Int32le
      # @!attribute ppi_fields
      #  @return [Type::String] concatenation of PPI fields
      define_attr :ppi_fields, BinStruct::String, builder: ->(h, t) { t.new(length_from: -> { h.length - 8 }) }
      # @!attribute body
      #  @return [Type::String]
      define_attr :body, BinStruct::String
      # @!attribute align
      #  @return [Boolean] align flag from {#flags} attribute
      define_bit_attrs_on :flags, :reserved, 7, :align

      # Check version field
      # @see [Base#parse?]
      def parse?
        version.zero? && (length >= 8)
      end

      # Calculate header length
      # @return [Integer] calculated length
      # @since 2.1.3
      def calc_length
        self[:length].value = self.sz - self[:body].sz
      end

      # send PPI packet on wire. Dot11 FCS trailer should be set.
      # @param [String] iface interface name
      # @return [void]
      def to_w(iface)
        Inject.inject(iface: iface, data: self)
      end
    end
    self.add_class PPI

    # Radiotap header (see http://www.radiotap.org/)
    # @author Sylvain Daubert
    # @since 1.4.0
    class RadioTap < Base
      # @!attribute version
      #  @return [Integer] 8-bit version
      define_attr :version, BinStruct::Int8, default: 0
      # @!attribute pad
      #  @return [Integer] 8-bit pad
      define_attr :pad, BinStruct::Int8, default: 0
      # @!attribute length
      #  @return [Integer] 16-bit RadioTap header length
      define_attr :length, BinStruct::Int16le, default: 8
      # @!attribute present_flags
      #  @return [Integer] 32-bit integer
      define_attr :present_flags, BinStruct::Int32le
      # @!attribute radio_fields
      #  @return [Type::String] concatenation of RadioTap fields
      define_attr :radio_fields, BinStruct::String, builder: ->(h, t) { t.new(length_from: -> { h.length - 8 }) }
      # @!attribute body
      #  @return [Type::String]
      define_attr :body, BinStruct::String

      # Check version field
      # @see [Base#parse?]
      def parse?
        version.zero? && (length >= 8)
      end

      # Calculate header length
      # @return [Integer] calculated length
      # @since 2.1.3
      def calc_length
        self[:length].value = self.sz - self[:body].sz
      end

      # send RadioTap packet on wire. Dot11 FCS trailer should be set.
      # @param [String] iface interface name
      # @return [void]
      def to_w(iface)
        Inject.inject(iface: iface, data: self)
      end
    end
    self.add_class RadioTap

    # IEEE 802.11 header
    # @abstract This is a base class to demultiplex different IEEE 802.11 frames when
    #   parsing.
    # A IEEE 802.11 header may consist of at least:
    # * a {#frame_ctrl} ({BinStruct::Int16}),
    # * a {#id}/duration ({BinStruct::Int16le}),
    # * and a {#mac1} ({Eth::MacAddr}).
    # Depending on frame type and subtype, it may also contains:
    # * a {#mac2} ({Eth::MacAddr}),
    # * a {#mac3} ({Eth::MacAddr}),
    # * a {#sequence_ctrl} ({BinStruct::Int16}),
    # * a {#mac4} ({Eth::MacAddr}),
    # * a {#qos_ctrl} ({BinStruct::Int16}),
    # * a {#ht_ctrl} ({BinStruct::Int32}),
    # * a {#body} (a {BinStruct::String} or another {Base} class),
    # * a Frame check sequence ({#fcs}, of type {BinStruct::Int32le})
    #
    # == Header accessors
    # As Dot11 header types are defined under Dot11 namespace, Dot11 header accessors
    # have a specific name. By example, to access to a {Dot11::Beacon} header,
    # accessor is +#dot11_beacon+.
    #
    # == Create Dot11 packets
    # As {Dot11} is an abstract class, you have to use one of its subclasses to
    # instanciate a IEEE802.11 header.
    #
    # === IEEE802.11 control frames
    # Control frames may be created this way:
    #   pkt = PacketGen.gen('Dot11::Control', subtype: 13) # Ack control frame
    #   pkt.dot11_control     # => PacketGen::Header::Dot11::Control
    #   # #dot11 is a shortcut for #dot11_control
    #   pkt.dot11             # => PacketGen::Header::Dot11::Control
    #
    # === IEEE802.11 management frames
    # Management frames may be created this way:
    #   pkt = PacketGen.gen('Dot11::Management')
    #   pkt.dot11_management     # => PacketGen::Header::Dot11::Management
    #   # #dot11 is a shortcut for #dot11_management
    #   pkt.dot11                # => PacketGen::Header::Dot11::Management
    # Management frames are usually specialized, AssociationRequest by example:
    #   pkt.add('Dot11::AssoReq')
    #   pkt.dot11_assoreq        # => PacketGen::Header::Dot11::AssoReq
    # Management frames also may contain some elements (see IEEE 802.11 standard):
    #   pkt.dot11_assoreq.add_elements(type: 'SSID', value: "My SSID")
    #   pkt.dot11_assoreq.add_elements(type: 'Rates', value: supported_rates)
    #
    # === IEEE802.11 data frames
    # Data frames may be created this way:
    #   pkt = PacketGen.gen('Dot11::Data')
    #   pkt.dot11_data     # => PacketGen::Header::Dot11::Data
    #   # #dot11 is a shortcut for #dot11_data
    #   pkt.dot11          # => PacketGen::Header::Dot11::Data
    #
    # == Parse Dot11 packets
    # When parsing a Dot11 packet, Dot11 subclass is created from +type+ value.
    # Dot11 header should then be accessed through +Packet#dot11+, whatever
    # the frame type is. But, specialized methods also exist: by example,
    # for a control frame, +Packet#dot11_control+ may also be used.
    #
    # == Send Dot11 packets
    # To send a Dot11 packet, a RadioTap header is needed:
    #   pkt = PacketGen.gen('RadioTap')
    #   pkt.add('Dot11::Management', mac1: client, mac2: bssid, mac3: bssid)
    #   pkt.add('Dot11::Beacon')
    #   pkt.dot11_beacon.add_element(type: 'SSID', value: 'My SSID')
    #   pkt.dot11_beacon.add_element(type: 'Rates', value: "\x85\x0c")
    #   pkt.calc
    #   pkt.to_w('wlan0')
    # @author Sylvain Daubert
    # @since 1.4.0
    class Dot11 < Base
      # Frame types
      TYPES = %w[Management Control Data Reserved].freeze

      class << self
        # Set a flag for parsing Dot11 packets. If set to +true+, parse FCS field,
        # else don't. Default is +true+.
        # @return [Boolean]
        attr_accessor :fcs
        alias fcs? fcs
      end
      Dot11.fcs = true

      # @!attribute frame_ctrl
      #  @return [Integer] 16-bit frame control word
      define_attr :frame_ctrl, BinStruct::Int16, default: 0
      # @!attribute id
      #  @return [Integer] 16-bit ID/Duration word
      define_attr :id, BinStruct::Int16le, default: 0
      # @!attribute mac1
      #  @return [Eth::MacAddr]
      define_attr :mac1, Eth::MacAddr
      # @!attribute mac2
      #  @return [Eth::MacAddr]
      define_attr :mac2, Eth::MacAddr
      # @!attribute mac3
      #  @return [Eth::MacAddr]
      define_attr :mac3, Eth::MacAddr
      # @!attribute sequence_ctrl
      #  @return [Integer] 16-bit sequence control word
      define_attr :sequence_ctrl, BinStruct::Int16le, default: 0
      # @!attribute mac4
      #  @return [Eth::MacAddr]
      define_attr :mac4, Eth::MacAddr
      # @!attribute qos_ctrl
      #  @return [Integer] 16-bit QoS control word
      define_attr :qos_ctrl, BinStruct::Int16
      # @!attribute ht_ctrl
      #  @return [Integer] 16-bit HT control word
      define_attr :ht_ctrl, BinStruct::Int32
      # @!attribute body
      #  @return [BinStruct::String]
      define_attr :body, BinStruct::String
      # @!attribute fcs
      #  @return [BinStruct::Int32le]
      define_attr :fcs, BinStruct::Int32le

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
      define_bit_attrs_on :frame_ctrl, :subtype, 4, :type, 2, :proto_version, 2,
                          :order, :wep, :md, :pwmngt, :retry, :mf, :from_ds, :to_ds

      # @!attribute sequence_number (12-bit field from {#sequence_ctrl})
      #  @return [Integer]
      #  @since 2.1.3
      # @!attribute fragment_number (4-bit field from {#sequence_ctrl})
      #  @return [Integer]
      #  @since 2.1.3
      define_bit_attrs_on :sequence_ctrl, :sequence_number, 12, :fragment_number, 4

      alias duration id
      # @private
      alias old_attributes attributes

      # @param [Hash] options
      # @see Base#initialize
      def initialize(options={})
        super
        @applicable_attributes = old_attributes
      end

      # Get all used field names
      # @return [Array<Symbol>]
      def attributes
        @applicable_attributes
      end

      # @private
      alias old_read read

      # Populate object from a binary string
      # @param [String] str
      # @return [Dot11] may return a subclass object if a more specific class
      #   may be determined
      def read(str)
        fcs = Dot11.fcs?

        if self.instance_of? Dot11
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
            private_read str, fcs
          end
        else
          private_read str, fcs
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
        define_applicable_attributes
        @applicable_attributes.map { |f| force_binary @attributes[f].to_s }.join
      end

      # Get human readable type
      # @return [String]
      def human_type
        TYPES[type]
      end

      # @return [String]
      def inspect
        str = if self.instance_of? Dot11
                Inspect.dashed_line("#{self.class} #{human_type}", 1)
              elsif self.respond_to? :human_subtype
                Inspect.dashed_line("#{self.class} #{human_subtype}", 1)
              else
                Inspect.dashed_line(self.class.to_s, 1)
              end

        define_applicable_attributes
        @applicable_attributes.each do |attr|
          next if attr == :body

          str << Inspect.inspect_attribute(attr, @attributes[attr], 1)
        end
        str
      end

      # send Dot11 packet on wire.
      # @param [String] iface interface name
      # @return [void]
      def to_w(iface)
        Inject.inject(iface: iface, data: self)
      end

      # Callback called when a Dot11 header is added to a packet
      # Here, add +#dot11+ method as a shortcut to existing
      # +#dot11_(control|management|data)+.
      # @param [Packet] packet
      # @return [void]
      def added_to_packet(packet)
        return if packet.respond_to? :dot11

        packet.instance_eval("def dot11(arg=nil); header(#{self.class}, arg); end") # def dot11(arg=nil); header(Dot11, arg); end
      end

      private

      def remove_from_applicable_attributes(attributes)
        attributes = [attributes] unless attributes.is_a? Array
        @applicable_attributes -= attributes
      end

      def handle_mac4
        if to_ds? && from_ds?
          @applicable_attributes[6, 0] = :mac4 unless @applicable_attributes.include? :mac4
        else
          remove_from_applicable_attributes :mac4
        end
      end

      def handle_ht_ctrl
        if order?
          unless @applicable_attributes.include? :ht_ctrl
            idx = @applicable_attributes.index(:body)
            @applicable_attributes[idx, 0] = :ht_ctrl
          end
        else
          remove_from_applicable_attributes %i[ht_ctrl]
        end
      end

      def handle_fcs
        if Dot11.fcs?
          @applicable_attributes << :fcs unless @applicable_attributes.include? :fcs
        else
          remove_from_applicable_attributes :fcs
        end
      end

      def define_applicable_attributes
        handle_mac4
        handle_ht_ctrl
        handle_fcs
      end

      def private_read(str, fcs)
        self[:frame_ctrl].read str[0, 2]
        define_applicable_attributes
        if fcs
          old_read str[0...-4]
          self[:fcs].read str[-4..]
        else
          old_read str
        end
        self
      end
    end

    self.add_class Dot11
    PPI.bind Dot11, dlt: PcapNG::LINKTYPE_IEEE802_11
    RadioTap.bind Dot11
  end
end

require_relative 'dot11/element'
require_relative 'dot11/management'
require_relative 'dot11/sub_mngt'
require_relative 'dot11/control'
require_relative 'dot11/data'
