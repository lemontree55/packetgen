# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    module HTTP
      # An HTTP/1.1 Request packet consists of:
      # * the http verb ({Types::String}).
      # * the path ({Types::String}).
      # * the version ({Types::String}).
      # * associated http headers ({HTTP::Headers}).
      #
      # == Create a HTTP Request header
      #   # standalone
      #   http_rqst = PacketGen::Header::HTTP::Request.new
      #   # in a packet
      #   pkt = PacketGen.gen("IP").add("TCP").add("HTTP::Request")
      #   # access to HTTP Request header
      #   pkt.http_request # => PacketGen::Header::HTTP::Request
      #
      # Note: When creating a HTTP Request packet, +sport+ and +dport+
      # attributes of TCP header are not set.
      #
      # == HTTP Request attributes
      #   http_rqst.version = "HTTP/1.1"
      #   http_rqst.verb  = "GET"
      #   http_rqst.path    = "/meow.html"
      #   http_rqst.headers = "Host: tcpdump.org"     # string or
      #   http_rqst.headers = { "Host": "tcpdump.org" } # even a hash
      #
      # @author Kent 'picat' Gruber
      # @author Sylvain Daubert
      # @since 3.1.0 Rename +#method+ into {#verb} to not mask +Object#method+.
      class Request < Base
        # @!attribute verb
        #   @return [Types::String]
        #   @since 3.1.0
        define_field :verb, Types::String
        # @!attribute path
        #   @return [Types::String]
        define_field :path,    Types::String
        # @!attribute version
        #   @return [Types::String]
        define_field :version, Types::String, default: 'HTTP/1.1'
        # @!attribute headers
        #   associated http/1.1 headers
        #   @return [HTTP::Headers]
        define_field :headers, HTTP::Headers
        # @!attribute body
        #   @return [Types::String]
        define_field :body, Types::String

        # @param [Hash] options
        # @option options [String] :verb
        # @option options [String] :path
        # @option options [String] :version
        # @option options [Hash]   :headers
        def initialize(options={})
          super(options)
          self.headers ||= options[:headers]
        end

        # Read in the HTTP portion of the packet, and parse it.
        # @return [PacketGen::HTTP::Request]
        def read(str)
          lines = lines(str)
          first_line_words = lines.shift.split
          self[:verb].read first_line_words[0]
          self[:path].read first_line_words[1]
          self[:version].read first_line_words[2]

          # requests can sometimes have a payload
          headers, data = headers_and_payload_from_lines(lines)
          self[:headers].read(headers)
          self[:body].read(data)

          self
        end

        def parse?
          VERBS.include?(self.verb) && self.version.start_with?('HTTP/1.')
        end

        # String representation of data.
        # @return [String]
        def to_s
          raise FormatError, 'Missing #verb.' if self.verb.empty?
          raise FormatError, 'Missing #path.'    if self.path.empty?
          raise FormatError, 'Missing #version.' if self.version.empty?

          "#{self.verb.dup} #{self.path} #{self.version}\r\n#{self[:headers]}#{self.body}"
        end

        private

        # @todo check verb is correct or raise a ParseError
        def lines(str)
          str = str.bytes.map!(&:chr).join unless str.valid_encoding?
          # vrb = HTTP::VERBS.detect { |verb| str.include?(verb) }

          str.split("\r\n").map(&:chomp)
        end

        def headers_and_payload_from_lines(lines)
          if (data_index = lines.find_index(''))
            data    = lines[data_index + 1..].join("\n")
            headers = lines[0..data_index - 1].join("\n")
          else
            headers = lines.join("\n")
            data = nil
          end

          [headers, data]
        end
      end
    end

    self.add_class HTTP::Request
    TCP.bind HTTP::Request, body: ->(b) { b.nil? ? '' : HTTP::REQUEST_REGEX =~ b }
  end
end
