# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class DHCP
      # define DHCP Options.
      # keys are option type, value are arrays containing option names
      # as strings, and a hash passed to {Option#initialize}.
      # @since 2.6.1
      DHCP_OPTIONS = {
        1  => ['subnet_mask', length: 4, v: IP::Addr],
        2  => ['time_zone'],
        3  => ['router', length: 4, v: IP::Addr],
        4  => ['time_server', length: 4, v: IP::Addr],
        5  => ['IEN_name_server', length: 4, v: IP::Addr],
        6  => ['name_server', length: 4, v: IP::Addr],
        7  => ['log_server', length: 4, v: IP::Addr],
        8  => ['cookie_server', length: 4, v: IP::Addr],
        9  => ['lpr_server', length: 4, v: IP::Addr],
        12 => ['hostname'],
        14 => ['dump_path'],
        15 => ['domain'],
        17 => ['root_disk_path'],
        23 => ['default_ttl'],
        24 => ['pmtu_timeout'],
        28 => ['broadcast_address', length: 4, v: IP::Addr],
        40 => ['NIS_domain'],
        41 => ['NIS_server', length: 4, v: IP::Addr],
        42 => ['NTP_server', length: 4, v: IP::Addr],
        43 => ['vendor_specific'],
        44 => ['NetBIOS_server', length: 4, v: IP::Addr],
        45 => ['NetBIOS_dist_server', length: 4, v: IP::Addr],
        50 => ['requested_addr', length: 4, v: IP::Addr],
        51 => ['lease_time', length: 4, v: Types::Int32, value: 43_200],
        53 => ['message-type', length: 1, v: Types::Int8],
        54 => ['server_id', length: 4, v: IP::Addr],
        55 => ['param_req_list'],
        56 => ['error_message'],
        57 => ['max_dhcp_size', length: 2, v: Types::Int16, value: 1_500],
        58 => ['renewal_time', length: 4, v: Types::Int32, value: 21_600],
        59 => ['rebinding_time', length: 4, v: Types::Int32, value: 37_800],
        60 => ['vendor_class_id'],
        61 => ['client_id'],
        64 => ['NISplus_domain'],
        65 => ['NISplus_server', length: 4, v: IP::Addr],
        69 => ['SMTP_server', length: 4, v: IP::Addr],
        70 => ['POP3_server', length: 4, v: IP::Addr],
        71 => ['NNTP_server', length: 4, v: IP::Addr],
        72 => ['WWW_server', length: 4, v: IP::Addr],
        73 => ['finger_server', length: 4, v: IP::Addr],
        74 => ['IRC_server', length: 4, v: IP::Addr]
      }.freeze

      # @deprecated Use {DHCP_OPTIONS} instead
      DCHPOptions = DHCP_OPTIONS

      # Class to indicate DHCP options end
      class End < Types::Int8
        def initialize(value=255)
          super
        end

        def to_human
          self.class.to_s.sub(/.*::/, '').downcase
        end
        alias human_type to_human
      end

      # Class to indicate padding after DHCP options
      class Pad < End
        def initialize(value=0)
          super
        end
      end

      # DHCP option
      #
      # A DHCP option is a {Types::TLV TLV}, so it has:
      # * a {#type} ({Types::Int8}),
      # * a {#length} ({Types::Int8}),
      # * and a {#value}. Defalt type is {Types::String} but some options
      #   may use more suitable type (by example, a {IP::Addr} for +router+
      #   option).
      # @author Sylvain Daubert
      class Option < Types::TLV
        # Option types
        TYPES = Hash[DHCP_OPTIONS.to_a.map { |type, ary| [type, ary[0]] }]

        # @param [Hash] options
        # @option options [Integer] :type
        # @option options [Integer] :length
        # @option options [String] :value
        def initialize(options={})
          super
          return unless DHCP_OPTIONS.key?(self.type)
          h = DHCP_OPTIONS[self.type].last

          return unless h.is_a? Hash
          h.each do |k, v|
            self.length = v if k == :length
            if k == :v
              self[:value] = v.new
              self.value = options[:value] if options[:value]
            end
          end
        end

        # @private
        alias private_read read

        # Populate object from a binary string
        # @param [String] str
        # @return [Option,End,Pad] may return another object than itself
        def read(str)
          read_type = str[0].unpack('C').first
          if read_type.zero?
            Pad.new.read(str)
          elsif read_type == 255
            End.new.read(str)
          elsif DHCP_OPTIONS.key?(read_type)
            Option.new(DHCP_OPTIONS[read_type][1] || {}).private_read(str)
          else
            super
          end
        end

        def has_human_types?
          true
        end

        def human_type
          if DHCP_OPTIONS.key?(type)
            DHCP_OPTIONS[type].first.dup
          else
            type.to_s
          end
        end

        def to_human
          s = human_type
          if length > 0
            s << if value.respond_to? :to_human
                   ":#{value.to_human}"
                 elsif self[:value].is_a? Types::Int
                   ":#{self.value.to_i}"
                 else
                   ":#{value.inspect}"
                 end
          end
          s
        end
      end
    end
  end
end
