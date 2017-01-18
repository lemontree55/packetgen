# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    # A ICMP header consists of:
    # * a {#type} field ({Int8} type),
    # * a {#code} field ({Int8} type),
    # * a {#checksum} field ({Int16} type),
    # * and a {#body}.
    #
    # == Create a ICMP header
    #  # standalone
    #  icmp = PacketGen::Header::ICMP.new
    #  # in a packet
    #  pkt = PacketGen.gen('IP').add('ICMP')
    #  # access to ICMP header
    #  pkt.icmp     # => PacketGen::Header::ICMP
    #
    # == ICMP attributes
    #  icmp.code = 0
    #  icmp.type = 200
    #  icmp.checksum = 0x248a
    #  icmp.body.read 'this is a body'
    # @author Sylvain Daubert
    class ICMP < Base

      # ICMP internet protocol number
      IP_PROTOCOL = 1

      # @!attribute type
      #  8-bit ICMP type
      #  @return [Integer]
      define_field :type, StructFu::Int8
      # @!attribute code
      #  8-bit ICMP code
      #  @return [Integer]
      define_field :code, StructFu::Int8
      # @!attribute checksum
      #  16-bit ICMP checksum
      #  @return [Integer]
      define_field :checksum, StructFu::Int16
      # @!attribute body
      #  @return [StructFu::String,Header::Base]
      define_field :body, StructFu::String

      # Compute checksum and set +checksum+ field
      # @return [Integer]
      def calc_checksum
        sum = (type << 8) | code

        payload = body.to_s
        payload << "\x00" unless payload.size % 2 == 0
        payload.unpack('n*').each { |x| sum += x }

        while sum > 0xffff do
          sum = (sum & 0xffff) + (sum >> 16)
        end
        sum = ~sum & 0xffff
        self[:checksum].value = (sum == 0) ? 0xffff : sum
      end
    end

    self.add_class ICMP

    IP.bind_header ICMP, protocol: ICMP::IP_PROTOCOL
  end
end
