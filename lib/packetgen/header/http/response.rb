# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    module HTTP
      # An HTTP/1.1 Response packet consists of:
      # * the version ({BinStruct::String}).
      # * the status code ({BinStruct::String}).
      # * the status message ({BinStruct::String}).
      # * associated http headers ({HTTP::Headers}).
      # * the actual http payload body ({BinStruct::String}).
      #
      # == Create a HTTP Response header
      #   # standalone
      #   http_resp = PacketGen::Header::HTTP::Response.new
      #   # in a packet
      #   pkt = PacketGen.gen("IP").add("TCP").add("HTTP::Response")
      #   # access to HTTP Response header
      #   pkt.http_response # => PacketGen::Header::HTTP::Response
      #
      # Note: When creating a HTTP Response packet, +sport+ and +dport+
      # attributes of TCP header are not set.
      #
      # == HTTP Response attributes
      #   http_resp.version     = "HTTP/1.1"
      #   http_resp.status_code = "200"
      #   http_resp.status_mesg = "OK"
      #   http_resp.body        = "this is a body"
      #   http_resp.headers     = "Host: tcpdump.org"     # string or
      #   http_resp.headers     = { "Host": "tcpdump.org" } # even a hash
      #
      # @author Kent 'picat' Gruber
      class Response < Base
        # @!attribute version
        #   @return [BinStruct::String]
        define_attr :version,     BinStruct::String, default: 'HTTP/1.1'
        # @!attribute status_code
        #   @return [BinStruct::String]
        define_attr :status_code, BinStruct::String
        # @!attribute status_mesg
        #   @return [BinStruct::String]
        define_attr :status_mesg, BinStruct::String
        # @!attribute headers
        #   associated http/1.1 headers
        #   @return [BinStruct::String]
        define_attr :headers, HTTP::Headers
        # @!attribute body
        #   @return [HTTP::PHeaders]
        define_attr :body, BinStruct::String

        # @param [Hash] options
        # @option options [String] :version
        # @option options [String] :status_code
        # @option options [String] :status_mesg
        # @option options [String] :body
        # @option options [Hash]   :headers
        def initialize(options={})
          super
          self.headers ||= options[:headers]
        end

        # Read in the HTTP portion of the packet, and parse it.
        # @return [PacketGen::HTTP::Response]
        def read(str)
          headers, data = collect_headers_and_data(str)

          unless headers.empty?
            extract_info_from_first_line(headers)
            self[:headers].read(headers.join("\n"))
          end
          self[:body].read data.join("\n")

          self
        end

        def parse?
          version.start_with?('HTTP/1.')
        end

        # String representation of data.
        # @return [String]
        def to_s
          raise_on_bad_version_status

          str = +''
          str << self.version << ' ' << self.status_code << ' ' << self.status_mesg << "\r\n"
          str << self[:headers].to_s if self[:headers].given?
          str << self.body
        end

        private

        def collect_headers_and_data(str)
          headers = [] # header stream
          data = [] # data stream
          switch = false

          str = str.bytes.map!(&:chr).join unless str.valid_encoding?
          arr = str.split("\r\n")

          arr.each do |line|
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

          [headers, data]
        end

        def extract_info_from_first_line(headers)
          first_line = headers.shift.split
          return if first_line.size < 3

          self[:version].read first_line[0]
          self[:status_code].read first_line[1]
          self[:status_mesg].read first_line[2..].join(' ')
        end

        def raise_on_bad_version_status
          raise FormatError, 'Missing #status_code.' if self.status_code.empty?
          raise FormatError, 'Missing #status_mesg.' if self.status_mesg.empty?
          raise FormatError, 'Missing #version.'     if self.version.empty?
        end
      end
    end

    self.add_class HTTP::Response
    TCP.bind HTTP::Response, body: ->(b) { b.nil? ? '' : %r[^HTTP/1\.1\s\d{3,}\s.+] =~ b }
  end
end
