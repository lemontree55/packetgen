# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class IPv6
      # Base class to handle IPv6 extensions
      # @abstract You should not use this class but its subclasses.
      # A IPv6 extension header has the following format:
      #   0                   1                   2                   3
      #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #  |  Next Header  |  Hdr Ext Len  |                               |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
      #  |                                                               |
      #  .                                                               .
      #  .                            Options                            .
      #  .                                                               .
      #  |                                                               |
      #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #
      # Such a header consists of:
      # * a {#next} header field ({Types::Int8}),
      # * a {#length} field ({Types::Int8}),
      # * an {#options} field ({Types::String}),
      # * and a {#body}, containing next header.
      # @author Sylvain Daubert
      class Extension < Base
        # @!attribute next
        #  8-bit Next header field
        #  @return [Integer]
        define_field :next, Types::Int8
        # @!attribute length
        #  8-bit extension length, in 8-octets units, not including the
        #  first 8 octets.
        #  @return [Integer]
        define_field :length, Types::Int8
        # @!attribute options
        #  Specific options of extension header
        #  @return [String]
        define_field :options, Types::String,
                     builder: ->(h, t) { t.new(length_from: ->() { h.real_length }) }
        # @!attribute body
        #  @return [String,Base]
        define_field :body, Types::String

        # Get real extension header length
        # @return [Integer]
        def real_length
          (length + 1) * 8
        end

        # Compute length and set +len+ field
        # @return [Integer]
        def calc_length
          self.length = (options.sz + 2) / 8 - 1
        end
      end
    end
  end
end

require_relative 'hop_by_hop'
