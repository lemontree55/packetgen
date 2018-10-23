# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    module HTTP
      # An HTTP/1.1 Request packet consists of:
      # * the http method ({Types::String}).
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
      #   http_rqst.method  = "GET"
      #   http_rqst.path    = "/meow.html"
      #   http_rqst.headers = "Host: tcpdump.org"     # string or
      #   http_rqst.headers = { "Host": "tcpdump.org" } # even a hash
      #
      # @author Kent 'picat' Gruber
      class Request < Base
        # @!attribute method
        #   @return [Types::String]
        define_field :method,  Types::String
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
        # @option options [String] :method
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
          str = str.bytes.map!(&:chr).join unless str.valid_encoding?
          vrb = HTTP::VERBS.detect { |verb| str.include?(verb) }
          str = vrb + str.split(vrb)[-1]
          str = str.split("\n").map(&:chomp)
          first_line = str.shift.split
          self[:method].read first_line[0]
          self[:path].read first_line[1]
          self[:version].read first_line[2]
          # requests can sometimes have a payload
          if (data_index = str.find_index(''))
            data    = str[data_index + 1..-1].join("\n")
            headers = str[0..data_index - 1].join("\n")
          else
            headers = str.join("\n")
          end
          self[:headers].read(headers)
          self[:body].read data
          self
        end

        # String representation of data.
        # @return [String]
        def to_s
          raise FormatError, 'Missing #method.'  if self.method.empty?
          raise FormatError, 'Missing #path.'    if self.path.empty?
          raise FormatError, 'Missing #version.' if self.version.empty?
          str = ''.dup # build 'dat string
          str << self[:method] << ' ' << self[:path] << ' ' << self[:version] << "\r\n" << self[:headers].to_s << self[:body]
        end
      end
    end

    self.add_class HTTP::Request
    TCP.bind HTTP::Request, body: ->(b) { HTTP::REQUEST_REGEX =~ b.chars.select(&:valid_encoding?).join }
  end
end
