# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    # Dynamic Host Configuration Protocol for IPv6, {https://tools.ietf.org/html/rfc3315
    # RFC 3315}
    #
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |    msg-type   |               transaction-id                  |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   .                            options                            .
    #   .                           (variable)                          .
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # A DHCPv6 header is made of:
    # * a {#msg_type} field ({Types::Int8Enum}),
    # * a {#transaction_id} field ({Types::Int24}),
    # * and an {#options} field ({DHCPv6::Options}).
    #
    # == Create a DHCPv6 header
    #   # standalone
    #  dhcpv6 = PacketGen::Header::DHCPv6.new(msg_type: 'SOLLICIT')
    #  # in a packet
    #  pkt = PacketGen.gen('IPv6').add('DHCPv6', msg_type: 'SOLLICIT')
    #  # access to DHCPv6 header from packet
    #  pkt.dhcpv6    #=> PacketGen::Header::DHCPv6
    #
    # == Add options
    # DHCPv6 options are defined by subclasses of {DHCPv6::Option}.
    #
    # Options may be added by pushing a hash to {#options}:
    #   dhcpv6 = PacketGen::Header::DHCPv6.new(msg_type: 'SOLLICIT')
    #   dhcpv6.options << { type: 'Preference', value: 1 }
    # @author Sylvain Daubert
    # @since 2.5.0
    class DHCPv6 < Base; end

    require_relative 'dhcpv6/duid'
    require_relative 'dhcpv6/option'
    require_relative 'dhcpv6/options'

    class DHCPv6
      # DHCPv6 UDP client port
      UDP_CLIENT_PORT = 546
      # DHCPv6 UDP client port
      UDP_SERVER_PORT = 547

      # DHCPv6 message types
      MESSAGE_TYPES = {
        'SOLLICIT'            => 1,
        'ADVERTISE'           => 2,
        'REQUEST'             => 3,
        'CONFIRM'             => 4,
        'RENEW'               => 5,
        'REBIND'              => 6,
        'REPLY'               => 7,
        'RELEASE'             => 8,
        'DECLINE'             => 9,
        'RECONFIGURE'         => 10,
        'INFORMATION-REQUEST' => 11
      }.freeze

      # @!attribute msg_type
      #   8-bit message type
      #   @return [Integer]
      define_field :msg_type, Types::Int8Enum, enum: MESSAGE_TYPES
      # @!attribute transaction_id
      #   24-bit transaction ID
      # @return [Integer]
      define_field :transaction_id, Types::Int24
      # @!attribute options
      #   @return [DHCPv6::Options]
      define_field :options, DHCPv6::Options

      # Populate object from string
      # @param [String] str
      # @return [DHCPv6,DHCPv6::Relay]
      def read(str)
        msg_type = Types::Int8.new.read(str)

        case msg_type
        when 12, 13
          DHCPv6::Relay.new.read(str)
        else
          super
        end
      end

      # Get human readable message type
      # @return [String]
      def human_msg_type
        self[:msg_type].to_human
      end
    end

    UDP.bind DHCPv6, sport: DHCPv6::UDP_CLIENT_PORT, dport: DHCPv6::UDP_SERVER_PORT
    UDP.bind DHCPv6, sport: DHCPv6::UDP_SERVER_PORT, dport: DHCPv6::UDP_CLIENT_PORT
  end
end

require_relative 'dhcpv6/relay'
