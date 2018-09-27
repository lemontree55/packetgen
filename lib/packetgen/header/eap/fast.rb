# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class EAP
      # Extensible Authentication Protocol (EAP) - Flexible Authentication variable
      # Secure Tunneling, {https://tools.ietf.org/html/rfc4851 RFC 4851}
      #
      # {EAP::FAST} has following fields:
      # * {#flags} ({Types::Int8}),
      # * optionally {#message_length} ({Types::Int32}), if +#l?+ is +true+,
      # * {#body} ({Types::String}).
      # @author Sylvain Daubert
      # @since 2.1.4
      class FAST < TTLS
        update_field :type, default: 43
      end
    end
  end
end
