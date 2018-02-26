# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    
    # Dynamic Host Configuration Protocol for IPv6, {https://tools.ietf.org/html/rfc3315 
    # RFC 3315}
    # @author Sylvain Daubert
    class DHCPv6 < Base;end

    require_relative 'dhcpv6/duid'
    require_relative 'dhcpv6/option'
    require_relative 'dhcpv6/options'

    class DHCPv6 
      UDP_CLIENT_PORT = 546
      UDP_SERVER_PORT = 547
      
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
        'INFORMATION-REQUEST' =>  11
      }
      
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

    UDP.bind_header DHCPv6, sport: DHCPv6::UDP_CLIENT_PORT, dport: DHCPv6::UDP_SERVER_PORT
    UDP.bind_header DHCPv6, sport: DHCPv6::UDP_SERVER_PORT, dport: DHCPv6::UDP_CLIENT_PORT
  end
end

require_relative 'dhcpv6/relay'
