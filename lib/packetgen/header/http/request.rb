# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    module HTTP
      # An HTTP/1.1 Request packet consists of:
      # * the http verb (+BinStruct::String+).
      # * the path (+BinStruct::String+).
      # * the version (+BinStruct::String+).
      # * associated http headers ({HTTP::Headers}).
      # * and a {#body} (+BinStruct::String+).
      #
      # Note: When creating a HTTP Request packet, {TCP#sport} and {TCP#dport}
      # attributes are not set.
      #
      # @example Create a HTTP Request header
      #   # standalone
      #   http_request = PacketGen::Header::HTTP::Request.new
      #   # in a packet
      #   pkt = PacketGen.gen("IP").add("TCP").add("HTTP::Request")
      #   # access to HTTP Request header
      #   pkt.http_request.class # => PacketGen::Header::HTTP::Request
      #
      # @example HTTP Request attributes
      #   http_request = PacketGen::Header::HTTP::Request.new
      #   http_request.version #=> "HTTP/1.1"
      #   http_request.verb  = "GET"
      #   http_request.path    = "/meow.html"
      #   http_request.headers = "Host: tcpdump.org"     # string or
      #   http_request.headers = { "Host": "tcpdump.org" } # even a hash
      #
      # @author Kent 'picat' Gruber
      # @author Sylvain Daubert
      # @author LemonTree55
      # @since 3.1.0 Rename +#method+ into {#verb} to not mask +Object#method+.
      class Request < Base
        # @!attribute verb
        #   HTTP verb (method)
        #   @return [BinStruct::String]
        #   @since 3.1.0
        define_attr :verb, BinStruct::String
        # @!attribute path
        #   Requested path
        #   @return [BinStruct::String]
        define_attr :path,    BinStruct::String
        # @!attribute version
        #   HTTP version
        #   @return [BinStruct::String]
        define_attr :version, BinStruct::String, default: 'HTTP/1.1'
        # @!attribute headers
        #   associated http/1.1 headers
        #   @return [HTTP::Headers]
        define_attr :headers, HTTP::Headers
        # @!attribute body
        #   HTTP request body, if any
        #   @return [BinStruct::String]
        define_attr :body, BinStruct::String

        # @param [Hash] options
        # @option options [String] :verb
        # @option options [String] :path
        # @option options [String] :version
        # @option options [Hash]   :headers
        def initialize(options={})
          super
          self.headers ||= options[:headers]
        end

        # Read in the HTTP portion of the packet, and parse it.
        # @return [self]
        def read(str)
          lines = lines(str)
          first_line_words = lines.shift.split
          self[:verb].read(first_line_words[0])
          self[:path].read(first_line_words[1])
          self[:version].read(first_line_words[2])

          # requests can sometimes have a payload
          headers, data = headers_and_payload_from_lines(lines)
          self[:headers].read(headers)
          self[:body].read(data)

          self
        end

        # May be parsed as a HTTP request if verb is known, and if version is +HTTP/1.x+.
        # @return [Boolean]
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
