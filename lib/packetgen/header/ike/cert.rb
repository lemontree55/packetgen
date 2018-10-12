# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class IKE
      # This class handles Certificate payloads.
      #
      # A Cert payload consists of the IKE generic payload header (see {Payload})
      # and some specific fields:
      #                        1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Next Payload  |C|  RESERVED   |         Payload Length        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Cert Encoding |                                               |
      #   +-+-+-+-+-+-+-+-+                                               +
      #   |                                                               |
      #   ~                       Certificate Data                        ~
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # These specific fields are:
      # * {#encoding},
      # * and {#content} (Certificate Data).
      #
      # == Create a Cert payload
      #   # Create a IKE packet with a Cert payload
      #   pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::Cert', encoding: 'X509_CERT_SIG')
      #   certs = cert.to_der << ca_cert.to_der
      #   pkt.ike_cert.content.read certs
      #   pkt.calc_length
      # @author Sylvain Daubert
      class Cert < Payload
        # Payload type number
        PAYLOAD_TYPE = 37

        ENCODINGS = {
          'PKCS7_WRAPPED_X509'   => 1,
          'PGP'                  => 2,
          'DNS_SIGNED_KEY'       => 3,
          'X509_CERT_SIG'        => 4,
          'KERBEROS_TOKEN'       => 6,
          'X509_CRL'             => 7,
          'X509_ARL'             => 8,
          'SPKI_CERT'            => 9,
          'X509_CERT_ATTR'       => 10,
          'HASH_URL_X509_CERT'   => 12,
          'HASH_URL_X509_BUNDLE' => 13
        }.freeze

        # @attribute encoding
        #   8-bit certificate encoding
        #   @return [Integer]
        define_field_before :content, :encoding, Types::Int8Enum, enum: ENCODINGS

        def initialize(options={})
          super
          self.encoding = options[:encoding] if options[:encoding]
        end

        # Get encoding name
        # @return [String]
        def human_encoding
          self[:encoding].to_human
        end
      end
    end

    self.add_class IKE::Cert
  end
end
