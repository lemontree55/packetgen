# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    module HTTP
      # An HTTP/1.1 Request packet consits of:
      # * the http method ({Types::String}).
      # * the path ({Types::String}).
      # * the version ({Types::String}).
      # * associated http headers ({Types::String}).
      #
      # == Create a HTTP Request header
      #   # standalone
      #   http_rqst = PacketGen::Header::HTTP::Request.new
      #   # in a packet
      #   pkt = PacketGen.gen("IP").add("TCP").add("HTTP::Request")
      #   # access to HTTP Request header
      #   pkt.http_request # => PacketGen::Header::HTTP::Request
      #
      # == HTTP Request attributes
      #	  http_rqst.version = "HTTP/1.1"
      #	  http_rqst.method = "GET"
      #	  http_rqst.path = "/meow.html"
      #   http_rqst.headers = "Host: tcpdump.org"     # string or
      #	  http_rqst.headers = { host: "tcpdump.org" } # even a hash
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
        define_field :version, Types::String
        # @!attribute headers
        #   associated http/1.1 headers
        #   @return [Types::HTTPHeaders]
        define_field :headers, Types::HTTPHeaders 

        # Give it a pretty name, the only way I know how.
        # @return [String]
        def protocol_name
          "HTTP_Request"
        end

        # Read in the HTTP portion of the packet, and parse it. 
        # @return [PacketGen::HTTP::Request]
        def read(str)
          # prepare data to parse
          str = str.split("\n").map(&:strip).reject(&:empty?)
          first_line = str.shift.split
          self[:method]  = first_line[0]
          self[:path]    = first_line[1]
          self[:version] = first_line[2]
          headers = str.join("\n")
          self[:headers].read(headers)
          self
        end

        # String representation of data.
        # @return [String]
        def to_s
          raise FormatError, "Missing #method."  if self.method.empty?
          raise FormatError, "Missing #path."    if self.path.empty?
          raise FormatError, "Missing #version." if self.version.empty?
          str = "" # build 'dat string
          str << self[:method] << " " << self[:path] << " " << self[:version] << "\r\n" << self[:headers].to_s
        end
      end
    end

    self.add_class HTTP::Request 
    TCP.bind_header HTTP::Request, body: ->(b) { /^(CONNECT|DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT)/ =~ b }
  end
end

