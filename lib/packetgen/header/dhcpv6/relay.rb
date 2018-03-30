# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class DHCPv6
      # DHCPv6 Relay agent / server header
      # @author Sylvain Daubert
      class Relay < Base
        # DHCPv6 Relay message types
        MESSAGE_TYPES = {
          'RELAY-FORW' => 12,
          'RELAY-REPL' => 13
        }
        
        # @!attribute msg_type
        #   8-bit message type
        #   @return [Integer]
        define_field :msg_type, Types::Int8Enum, enum: MESSAGE_TYPES
        # @!attribute hop_count
        #   8-bit hop count (number of relay agents that have relayed
        #   this message)
        #   @return [Integer]
        define_field :hop_count, Types::Int8
        # @!attribute link
        #   Link address: address that will be used by the server to identify
        #   the link on which the client is located
        #   @return [IPv6::Addr]
        define_field :link, IPv6::Addr
        # @!attribute peer
        #   Peer address: the address of the client or relay agent from which
        #   the message to be relayed was received
        #   @return [IPv6::Addr]
        define_field :peer, IPv6::Addr
        # @!attribute options
        #   @return [DHCPv6::Options]
        define_field :options, DHCPv6::Options
      end
    end

    UDP.bind_header DHCPv6::Relay, sport: DHCPv6::UDP_CLIENT_PORT, dport: DHCPv6::UDP_SERVER_PORT
    UDP.bind_header DHCPv6::Relay, sport: DHCPv6::UDP_SERVER_PORT, dport: DHCPv6::UDP_CLIENT_PORT
  end
end
