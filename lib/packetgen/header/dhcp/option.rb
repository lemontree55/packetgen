# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class DHCP
      # Known DHCP options
      # @since 3.1.0
      DHCP_OPTIONS = {
        'pad' => 0,
        'subnet_mask' => 1,
        'time_zone' => 2,
        'router' => 3,
        'time_server' => 4,
        'IEN_name_server' => 5,
        'name_server' => 6,
        'log_server' => 7,
        'cookie_server' => 8,
        'lpr_server' => 9,
        'hostname' => 12,
        'dump_path' => 14,
        'domain' => 15,
        'root_disk_path' => 17,
        'default_ttl' => 23,
        'pmtu_timeout' => 24,
        'broadcast_address' => 28,
        'NIS_domain' => 40,
        'NIS_server' => 41,
        'NTP_server' => 42,
        'vendor_specific' => 43,
        'NetBIOS_server' => 44,
        'NetBIOS_dist_server' => 45,
        'requested_addr' => 50,
        'lease_time' => 51,
        'message-type' => 53,
        'server_id' => 54,
        'param_req_list' => 55,
        'error_message' => 56,
        'max_dhcp_size' => 57,
        'renewal_time' => 58,
        'rebinding_time' => 59,
        'vendor_class_id' => 60,
        'client_id' => 61,
        'NISplus_domain' => 64,
        'NISplus_server' => 65,
        'SMTP_server' => 69,
        'POP3_server' => 70,
        'NNTP_server' => 71,
        'WWW_server' => 72,
        'finger_server' => 73,
        'IRC_server' => 74,
        'end' => 255
      }.freeze

      # @!parse
      #  # Option class with string value. {#type #type} and {#length #length} are
      #  # {BinStruct::Int8}.
      #  #
      #  # See also {IPAddrOption}, {Int8Option}, {Int16Option} and {Int32Option}.
      #  # @since 2.2.0
      #  # @since 3.1.0 subclass of {BinStruct::AbstractTLV}
      #  class Option < BinStruct::AbstractTLV; end
      # @private
      Option = BinStruct::AbstractTLV.create
      Option.define_type_enum DHCP_OPTIONS
      # @!parse
      #  # {Option} class with IP address value
      #  # @since 2.2.0
      #  # @since 3.1.0 subclass of {BinStruct::AbstractTLV}
      #  class IPAddrOption < BinStruct::AbstractTLV; end
      # @private
      IPAddrOption = BinStruct::AbstractTLV.create(value_class: IP::Addr)
      IPAddrOption.define_type_enum DHCP_OPTIONS
      # @!parse
      #  # {Option} class with int8 value
      #  # @since 2.2.0
      #  # @since 3.1.0 subclass of {BinStruct::AbstractTLV}
      #  class Int8Option < BinStruct::AbstractTLV; end
      # @private
      Int8Option = BinStruct::AbstractTLV.create(value_class: BinStruct::Int8)
      Int8Option.define_type_enum DHCP_OPTIONS
      # @!parse
      #  # {Option} class with int16 value
      #  # @since 2.2.0
      #  # @since 3.1.0 subclass of {BinStruct::AbstractTLV}
      #  class Int16Option < BinStruct::AbstractTLV; end
      # @private
      Int16Option = BinStruct::AbstractTLV.create(value_class: BinStruct::Int16)
      Int16Option.define_type_enum DHCP_OPTIONS
      # @!parse
      #  # {Option} class with int32 value
      #  # @since 2.2.0
      #  # @since 3.1.0 subclass of {BinStruct::AbstractTLV}
      #  class Int32Option < BinStruct::AbstractTLV; end
      # @private
      Int32Option = BinStruct::AbstractTLV.create(value_class: BinStruct::Int32)
      Int32Option.define_type_enum DHCP_OPTIONS

      # Class to indicate DHCP options end
      class End < BinStruct::Int8
        def initialize(options={ value: 255 })
          super
        end

        def to_human
          self.class.to_s.sub(/.*::/, '').downcase
        end
        alias human_type to_human
      end

      # Class to indicate padding after DHCP options
      class Pad < End
        def initialize(options={ value: 0 })
          super
        end
      end
    end
  end
end
