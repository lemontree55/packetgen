# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class IKE
      # This class handles Certificate Request payloads.
      #
      # A CertReq payload consists of the IKE generic payload header (see {Payload})
      # and some specific fields:
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Next Payload  |C|  RESERVED   |         Payload Length        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Cert Encoding |                                               |
      #   +-+-+-+-+-+-+-+-+                                               +
      #   |                                                               |
      #   ~                      Certification Authority                  ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # These specific fields are:
      # * {#encoding},
      # * and {#content} (Certification Authority).
      #
      # == Create a CertReq payload
      #   # Create a IKE packet with a CertReq payload
      #   pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::CertReq', encoding: 'X509_CERT_SIG')
      #   pkt.ike_certreq.content.read OpenSSL::Digest::SHA1.digest(ca_cert.to_der)
      #   pkt.calc_length
      # @author Sylvain Daubert
      class CertReq < Cert
        # Payload type number
        PAYLOAD_TYPE = 38

        # Get list of 20-byte string (SHA-1 hashes)
        # @return [String]
        def human_content
          strs = []
          idx = 0
          while idx < content.size
            strs << content[idx, 20]
            idx += 20
          end
          strs.map(&:inspect).join(',')
        end

        # @return [String]
        def inspect
          str = Inspect.dashed_line(self.class, 2)
          fields.each do |attr|
            case attr
            when :body
              next
            when :content
              str << Inspect.shift_level(2)
              str << Inspect::FMT_ATTR % ['hashes', :content, human_content]
            else
              str << Inspect.inspect_attribute(attr, self[attr], 2)
            end
          end
          str
        end
      end
    end

    self.add_class IKE::CertReq
  end
end
