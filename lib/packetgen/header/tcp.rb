# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    # TCP header ({https://tools.ietf.org/html/rfc793 RFC 793})
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |          Source Port          |       Destination Port        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                        Sequence Number                        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                    Acknowledgment Number                      |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |  Data |           |U|A|P|R|S|F|                               |
    #   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    #   |       |           |G|K|H|T|N|N|                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |           Checksum            |         Urgent Pointer        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                    Options                    |    Padding    |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                             data                              |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # A TCP header consists of:
    # * a source port ({#sport}, {Types::Int16} type),
    # * a destination port ({#dport}, +Int16+ type),
    # * a sequence number ({#seqnum}, {Types::Int32} type),
    # * an acknownledge number ({#acknum}, +Int32+ type),
    # * a 16-bit field ({#u16}, +Int16+ type) composed of:
    #   * a 4-bit {#data_offset} self[attr],
    #   * a 3-bit {#reserved} field,
    #   * a 9-bit {#flags} field,
    # * a {#window} field (+Int16+ type),
    # * a {#checksum} field (+Int16+ type),
    # * a urgent pointer ({#urg_pointer}, +Int16+ type),
    # * an optional {#options} field ({Options} type),
    # * and a {#body} ({Types::String} type).
    #
    # == Create a TCP header
    #  # standalone
    #  tcph = PacketGen::Header::TCP.new
    #  # in a IP packet
    #  pkt = PacketGen.gen('IP').add('TCP')
    #  # access to TCP header
    #  pkt.tcp   # => PacketGen::Header::TCP
    #
    # == TCP attributes
    #  tcph.sport = 4500
    #  tcph.dport = 80
    #  tcph.seqnum = 43
    #  tcph.acknum = 0x45678925
    #  tcph.wsize = 0x240
    #  tcph.urg_pointer = 0x40
    #  tcph.body.read 'this is a body'
    #
    # == Flags
    # TCP flags may be accesed as a 9-bit integer:
    #  tcph.flags = 0x1002
    # Each flag may be accessed independently:
    #  tcph.flag_syn?    # => Boolean
    #  tcph.flag_rst = true
    #
    # == Options
    # {#options} TCP attribute is a {Options}. {Option} may added to it:
    #  tcph.options << PacketGen::Header::TCP::MSS.new(1250)
    # or:
    #  tcph.options << { opt: 'MSS', self[attr]: 1250 }
    # @author Sylvain Daubert
    class TCP < Base
    end
  end
end

# Need to load Options now, as this is used through define_bit_fields_on,
# which make a call to TCP.new, which needs Options
require_relative 'tcp/options'

module PacketGen
  module Header
    class TCP
      # IP protocol number for TCP
      IP_PROTOCOL = 6

      # @!attribute sport
      #  16-bit TCP source port
      #  @return [Integer]
      define_field :sport, Types::Int16
      # @!attribute dport
      #  16-bit TCP destination port
      #  @return [Integer]
      define_field :dport, Types::Int16
      # @!attribute seqnum
      #  32-bit TCP sequence number
      #  @return [Integer]
      define_field :seqnum, Types::Int32, default: ->(_) { rand(2**32) }
      # @!attribute acknum
      #  32-bit TCP acknowledgement number
      #  @return [Integer]
      define_field :acknum, Types::Int32
      # @!attribute u16
      #  @return [Integer] 16-bit word used by flags and bit fields
      define_field :u16, Types::Int16
      # @!attribute window
      #  16-bit TCP window size
      #  @return [Integer]
      define_field :window, Types::Int16
      # @!attribute checksum
      #  16-bit TCP checksum
      #  @return [Integer]
      define_field :checksum, Types::Int16
      # @!attribute urg_pointer
      #  16-bit TCP urgent data pointer
      #  @return [Integer]
      define_field :urg_pointer, Types::Int16
      # @!attribute options
      #  TCP options
      #  @return [Options]
      define_field :options, TCP::Options, builder: ->(h, t) { t.new(length_from: -> { h.data_offset > 5 ? (h.data_offset - 5) * 4 : 0 }) }
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String

      alias source_port sport
      alias source_port= sport=
      alias destination_port dport
      alias destination_port= dport=
      alias sequence_number seqnum
      alias sequence_number= seqnum=
      alias acknowledgement_number acknum
      alias acknowledgement_number= acknum=
      alias wsize window
      alias wsize= window=

      # Call {Base#initialize), then handle specific options to set +u16+ by part:
      # * +:data_offset+
      # * +:hlen+
      # * +:reserved+
      # * +:flags+
      # @param [Hash] options
      # @option options [Integer] :sport
      # @option options [Integer] :dport
      # @option options [Integer] :seqnum
      # @option options [Integer] :acknum
      # @option options [Integer] :data_offset
      # @option options [Integer] :reserved
      # @option options [Integer] :flags
      # @option options [Integer] :window
      # @option options [Integer] :checksum
      # @option options [Integer] :urg_pointer
      # @option options [String] :body
      def initialize(options={})
        opts = { data_offset: 5 }.merge!(options)
        super(opts)
      end

      # @!attribute data_offset
      #  @return [Integer] 4-bit data offset from {#u16}
      # @!attribute reserved
      #  @return [Integer] 3-bit reserved from {#u16}
      # @!attribute flags
      #  @return [Integer] 9-bit flags from {#u16}
      define_bit_fields_on :u16, :data_offset, 4, :reserved, 3, :flags, 9
      alias hlen data_offset
      alias hlen= data_offset=

      # @!attribute flag_ns
      #  @return [Boolean] 1-bit NS flag
      # @!attribute flag_cwr
      #  @return [Boolean] 1-bit CWR flag
      # @!attribute flag_ece
      #  @return [Boolean] 1-bit ECE flag
      # @!attribute flag_urg
      #  @return [Boolean] 1-bit URG flag
      # @!attribute flag_ack
      #  @return [Boolean] 1-bit ACK flag
      # @!attribute flag_psh
      #  @return [Boolean] 1-bit PSH flag
      # @!attribute flag_rst
      #  @return [Boolean] 1-bit RST flag
      # @!attribute flag_syn
      #  @return [Boolean] 1-bit SYN flag
      # @!attribute flag_fin
      #  @return [Boolean] 1-bit FIN flag
      define_bit_fields_on :u16, :_, 7, :flag_ns, :flag_cwr, :flag_ece, :flag_urg,
                           :flag_ack, :flag_psh, :flag_rst, :flag_syn, :flag_fin

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        sum = ip_header(self).pseudo_header_checksum
        sum += IP_PROTOCOL
        sum += self.sz
        sum += IP.sum16(self)
        self.checksum = IP.reduce_checksum(sum)
      end

      # Compute header length and set +data_offset+ field
      # @return [Integer]
      def calc_length
        self[:data_offset] = 5 + self[:options].sz / 4
      end

      # @return [String]
      def inspect
        super do |attr|
          next unless attr == :u16

          shift = Inspect.shift_level
          str = Inspect.inspect_attribute(attr, self[attr])
          doff = Inspect.int_dec_hex(data_offset, 1)
          str << shift << Inspect::FMT_ATTR % ['', 'data_offset', doff]
          str << shift << Inspect::FMT_ATTR % ['', 'reserved', reserved]
          str << shift << Inspect::FMT_ATTR % ['', 'flags', flags2string]
        end
      end

      # Invert source and destination port numbers
      # @return [self]
      # @since 2.7.0
      def reply!
        self[:sport], self[:dport] = self[:dport], self[:sport]
        self
      end

      private

      def flags2string
        flags = +''
        %w[ns cwr ece urg ack psh rst syn fin].each do |fl|
          flags << (send(:"flag_#{fl}?") ? fl[0].upcase : '.')
        end

        flags
      end
    end

    self.add_class TCP

    IP.bind TCP, protocol: TCP::IP_PROTOCOL
    IPv6.bind TCP, next: TCP::IP_PROTOCOL
  end
end
