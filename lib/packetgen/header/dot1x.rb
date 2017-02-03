# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    # IEEE 802.1X / EAPOL
    #
    # A IEEE 802.1X header consists of:
    # * a {#version} ({Types::Int8}),
    # * a packet {#type} ({Types::Int8}),
    # * a {#length} ({Types::Int16}),
    # * and a body (a {Types::String} or another Header class).
    # == Create a Dot1x header
    #   pkt1 = PacketGen.gen('Eth').add('Dot1x', type: 1)
    #   pkt2 = PacketGen.gen('Eth').add('Dot1x')
    #   pkt2.dot1x.type = 'EAP Packet'
    #   pkt2.dot1x.body.read 'body'
    # @author Sylvain Daubert
    class Dot1x < Base

      # IEEE 802.1X packet types
      TYPES = {
        0 => 'EAP Packet',
        1 => 'Start',
        2 => 'Logoff',
        3 => 'Key',
        4 => 'Encap-ASF-Alert'
      }

      # @!attribute version
      #  @return [Integer] 8-bit Protocol Version
      define_field :version, Types::Int8, default: 1
      # @!attribute type
      #  @return [Integer] 8-bit Packet Type
      define_field :type, Types::Int8
      # @!attribute length
      #  @return [Integer] 16-bit body length
      define_field :length, Types::Int16
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String

      # @private
      alias old_type= type=

      # Set type attribute
      # @param [String,Integer] type
      # @return [Integer]
      def type=(type)
        case type
        when Integer
          self.old_type = type
        else
          v = TYPES.key(type.to_s)
          raise ArgumentError, "unknown type #{type}" if v.nil?
          self.old_type = v
        end
      end

      # Get human readable type
      # @return [String]
      def human_type
        v = TYPES[self.type]
        v = self.type if v.nil?
        v.to_s
      end
    end

    Eth.bind_header Dot1x, ethertype: 0x888e
  end
end
