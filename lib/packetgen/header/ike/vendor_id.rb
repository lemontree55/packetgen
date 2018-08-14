# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class IKE
      # This class handles Vendor ID payloads, as defined in RFC 7296 §3.12.
      #
      # A Vendor ID payload contains a generic payload header (see {Payload})
      # and data field (type {Types::String}):
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Next Payload  |C|  RESERVED   |         Payload Length        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   ~                            VendorID Data                         ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #
      # == Create a Vendor ID payload
      #   # Create a IKE packet with a Vendor ID payload
      #   pkt = PacketGen.gen('IP').add('UDP').add('IKE')
      #   pkt.add('IKE::VendorID', data: "abcdefgh")
      # @author Sylvain Daubert
      class VendorID < Payload
        # Payload type number
        PAYLOAD_TYPE = 43
      end
    end

    self.add_class IKE::VendorID
  end
end
