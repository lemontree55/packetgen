# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    # Module to group all NetBIOS headers
    # @author Sylvain Daubert
    # @since 2.5.1
    module NetBIOS
      # NetBIOS Session Service messages.
      # @author Sylvain Daubert
      class Datagram < Base
        # Port number for NetBIOS Session Service over TCP
        UDP_PORT = 138

        # Datagram packet types
        TYPES = {
          'direct_unique' => 0x10,
          'direct_group' => 0x11,
          'broadcast' => 0x12,
          'error' => 0x13,
          'query_request' => 0x14,
          'positive_query_resp' => 0x15,
          'negative_query_resp' => 0x16,
        }.freeze

        # @!attribute type
        #  8-bit session packet type
        #  @return [Integer]
        define_field :type, Types::Int8Enum, enum: TYPES
        # @!attribute flags
        #  8-bit flags
        #  @return [Integer]
        define_field :flags, Types::Int8
        # @!attribute dgm_id
        #  16-bit next transaction ID for datagrams
        #  @return [Integer]
        define_field :dgm_id, Types::Int16
        # @!attribute src_ip
        #  Source IP address
        # @return [IP::Addr]
        define_field :src_ip, IP::Addr
        # @!attribute src_port
        #  Source port
        # @return [IP::Addr]
        define_field :src_port, Types::Int16
        # @!attribute dgm_length
        #  Length of data + second level of encoded names. Not present in error datagram.
        # @return [Integer]
        define_field :dgm_length, Types::Int16, optional: ->(h) { h.type != 0x13 }
        # @!attribute packet_offset
        # Not present in error datagram.
        # @return [Integer]
        define_field :packet_offset, Types::Int16, optional: ->(h) { h.type != 0x13 }
        # @!attribute error_code
        #  Error code. Only present in error datagrams.
        #  @return [Integer]
        define_field :error_code, Types::Int16, optional: ->(h) { h.type == 0x13 }
        # @!attribute src_name
        #  NetBIOS source name. Only present in direct_unique, direct_group and broadcast datagrams.
        #  @return []
        define_field :src_name, Name, default: '', optional: ->(h) { (h.type >= 0x10) && (h.type <= 0x12) }
        # @!attribute dst_name
        #  NetBIOS destination name. Present in all but error datagrams.
        #  @return []
        define_field :dst_name, Name, default: '', optional: ->(h) { h.type != 0x13 }
        # @!attribute body
        #  User data. Ony present in direct_unique, direct_group and broadcast datagrams.
        #  @return [String]
        define_field :body, Types::String, optional: ->(h) { (h.type >= 0x10) && (h.type <= 0x12) }

        # @!attribute :rsv
        #  4-bit rsv field. 4 upper bits of {#flags}
        #  @return [Integer]
        # @!attribute :snt
        #  2-bit SNT (Source end-Node Type) field from {#flags}.
        #  @return [Integer]
        # @!attribute f
        #  First packet flag. If set then this is first
        #  (and possibly only) fragment of NetBIOS datagram.
        #  @return [Boolean]
        # @!attribute m
        #  More flag. If set then more NetBIOS datagram
        #  fragments follow.
        #  @return [Boolean]
        define_bit_fields_on :flags, :rsv, 4, :snt, 2, :f, :m

        # Compute and set {#dgm_length} field
        # @return [Integer] calculated length
        def calc_length
          length = self[:body].sz
          length += self[:src_name].sz if is_present?(:src_name)
          length += self[:dst_name].sz if is_present?(:dst_name)
          self.dgm_length = length
        end
      end
      Header.add_class Datagram
      UDP.bind Datagram, dport: Datagram::UDP_PORT, sport: Datagram::UDP_PORT
    end
  end
end
