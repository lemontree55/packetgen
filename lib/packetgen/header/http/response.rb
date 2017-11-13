# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    module HTTP
      # An HTTP/1.1 Respose packet consits of:
      # * the version ({Types::String}).
      # * the status code ({Types::String}).
      # * the status message ({Types::String}).
      # * associated http headers ({Types::HTTPHeaders}).
      # * the actual http payload body ({Types::String}).
      #
      # == Create a HTTP Response header
      #   # standalone
      #   http_resp = PacketGen::Header::HTTP::Response.new
      #   # in a packet
      #   pkt = PacketGen.gen("IP").add("TCP").add("HTTP::Response")
      #   # access to HTTP Response header
      #   pkt.http_response # => PacketGen::Header::HTTP::Response
      #
      # == HTTP Response attributes
      #   http_resp.version = "HTTP/1.1"
      #   http_resp.status_code = "200"
      #   http_resp.status_mesg = "OK"
      #   http_resp.body = "this is a body"
      #   http_resp.headers = "Host: tcpdump.org"     # string or
      #   http_resp.headers = { host: "tcpdump.org" } # even a hash
      #
      # @author Kent 'picat' Gruber
      class Response < Base
        # @!attribute version 
        #   @return [Types::String]
        define_field :version,     Types::String, default: "HTTP/1.1"
        # @!attribute status_code 
        #   @return [Types::String]
        define_field :status_code, Types::String
        # @!attribute status_mesg 
        #   @return [Types::String]
        define_field :status_mesg, Types::String  
        # @!attribute headers
        #   associated http/1.1 headers
        #   @return [Types::String]
        define_field :headers, Types::HTTPHeaders
        # @!attribute body 
        #   @return [Types::HTTPHeaders]
        define_field :body, Types::String
        
        # @param [Hash] options
        # @option options [String] :version
        # @option options [String] :status_code
        # @option options [String] :status_mesg
        # @option options [String] :body
        # @option options [Hash]   :headers
        def initialize(options={})
          super(options)
          self.headers ||= options[:headers]
        end

        # Give it a pretty name, the only way I know how.
        # @return [String]
        def protocol_name
          "HTTP_Response"
        end

        # Read in the HTTP portion of the packet, and parse it. 
        # @return [PacketGen::HTTP::Response]
        def read(str)
          # prepare data to parse
          str     = str.split("\r\n")
          headers = [] # header stream
          data    = [] # data stream
          switch  = false
          str.each do |line|
            if line.empty?
              data << line if switch # already done
              switch = true
              next
            end
            case switch
            when true
              data << line
            else
              headers << line
            end
          end
          unless headers.empty?
            first_line = headers.shift.split
            self[:version]     = first_line[0]
            self[:status_code] = first_line[1]
            self[:status_mesg] = first_line[2..-1].join(" ")
            self[:headers].read(headers.join("\n")) 
          end
          self[:body] = data.join("\n")
          self
        end

        # String representation of data.
        # @return [String]
        def to_s
          raise FormatError, "Missing #status_code." if self.status_code.empty?
          raise FormatError, "Missing #status_mesg." if self.status_mesg.empty?
          raise FormatError, "Missing #version."     if self.version.empty? 
          str = "" # build 'dat string
          str << self[:version] << " " << self[:status_code] << " " << self[:status_mesg] << "\r\n" << self[:headers].to_s << self.body
        end
      end
    end

    self.add_class HTTP::Response
    TCP.bind_header HTTP::Response, body: ->(b) { /^HTTP\/1\.1\s\d{3,}\s.+/ =~ b }
  end
end

