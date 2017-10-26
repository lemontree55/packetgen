# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class Dot11

      # @abstract Base class for all subtype management frames
      # Subclasses of this class are used to specialize {Management}. A
      # +SubMngt+ class set +subtype+ field in Dot11 header and may add some
      # fields.
      #
      # All SubMngt subclasses have ability to have {Element}. These elements
      # may be accessed through {#elements}.
      # @author Sylvain Daubert
      class SubMngt < Base
        # @return [Array<Element>]
        attr_accessor :elements

        # @param [Hash] options
        # @see Base#initialize
        def initialize(options={})
          super
          @elements = []
        end

        # Populate object from binary string
        # @param [String] str
        # @return [SubMngt] self
        def read(str)
          super
          read_elements str[sz, str.size] || ''
          self
        end

        # @return [String]
        def to_s
          super + @elements.map(&:to_s).join
        end

        # @return [String]
        def inspect
          str = super
          str << Inspect.dashed_line('Dot11 Elements', 3)
          @elements.each do |el|
            str << Inspect.shift_level(4) << el.to_human << "\n"
          end
          str
        end
        
        # Add an {Element} to header
        # @param [Integer,String] type element type
        # @param [Object] value element value
        # @return [self]
        def add_element(type:, value:)
          element = Element.new(type: type, value: value)
          @elements << element
          self
        end

        private

        def read_elements(str)
          start = 0
          elsz = Element.new.sz
          while str.size - start >= elsz  do
            el = Element.new.read(str[start, str.size])
            @elements << el
            start += el.sz
          end
        end
      end

      # IEEE 802.11 Association Request frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 0.
      #
      # Add fields:
      # * {#cap} ({Types::Int16le}),
      # * {#listen_interval} ({Types::Int16le}).
      # @author Sylvain Daubert
      class AssoReq < SubMngt
        # @!attribute cap
        #  @return [Integer] 16-bit capabillities word
        define_field :cap, Types::Int16le
        # @!attribute listen_interval
        #  @return [Integer] 16-bit listen interval value
        define_field :listen_interval, Types::Int16le, default: 0x00c8
      end
      Header.add_class AssoReq
      Management.bind_header AssoReq, op: :and, type: 0, subtype: 0

      # IEEE 802.11 Association Response frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 1.
      #
      # Add fields:
      # * {#cap} ({Types::Int16le}),
      # * {#status} ({Types::Int16le}),
      # * {#aid} ({Types::Int16le}).
      # @author Sylvain Daubert
      class AssoResp < SubMngt
        # @!attribute cap
        #  @return [Integer] 16-bit capabillities word
        define_field :cap, Types::Int16le
        # @!attribute status
        #  @return [Integer] 16-bit status word
        define_field :status, Types::Int16le
        # @!attribute aid
        #  @return [Integer] 16-bit AID word
        define_field :aid, Types::Int16le
      end
      Header.add_class AssoResp
      Management.bind_header AssoResp, op: :and, type: 0, subtype: 1

      # IEEE 802.11 ReAssociation Request frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 2.
      #
      # Add fields:
      # * {#cap} ({Types::Int16le}),
      # * {#listen_interval} ({Types::Int16le}),
      # * {#current_ap} ({Eth::MacAddr}).
      # @author Sylvain Daubert
      class ReAssoReq < AssoReq
        # @!attribute current_ap
        #  @return [Eth::MAcAddr]
        define_field :current_ap, Eth::MacAddr
      end
      Header.add_class ReAssoReq
      Management.bind_header ReAssoReq, op: :and, type: 0, subtype: 2

      # IEEE 802.11 ReAssociation Response frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 3.
      #
      # Add fields:
      # * {#cap} ({Types::Int16le}),
      # * {#status} ({Types::Int16le}),
      # * {#aid} ({Types::Int16le}).
      # @author Sylvain Daubert
      class ReAssoResp < AssoResp
      end
      Header.add_class ReAssoResp
      Management.bind_header ReAssoResp, op: :and, type: 0, subtype: 3

      # IEEE 802.11 Probe Request frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 4.
      #
      # This class adds no field.
      # @author Sylvain Daubert
      class ProbeReq < SubMngt
      end
      Header.add_class ProbeReq
      Management.bind_header ProbeReq, op: :and, type: 0, subtype: 4

      # IEEE 802.11 Probe Response frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 5.
      #
      # Add fields:
      # * {#timestamp} ({Types::Int64le}),
      # * {#beacon_interval} ({Types::Int16le}),
      # * {#cap} ({Types::Int16le}).
      # @author Sylvain Daubert
      class ProbeResp < SubMngt
        # @!attribute timestamp
        #  @return [Integer] 64-bit timestamp
        define_field :timestamp, Types::Int64le
        # @!attribute beacon_interval
        #  @return [Integer] 16-bit beacon interval value
        define_field :beacon_interval, Types::Int16le, default: 0x0064
        # @!attribute cap
        #  @return [Integer] 16-bit capabillities word
        define_field :cap, Types::Int16le
      end
      Header.add_class ProbeResp
      Management.bind_header ProbeResp, op: :and, type: 0, subtype: 5

      # IEEE 802.11 Beacon frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 8.
      #
      # Add fields:
      # * {#timestamp} ({Types::Int64le}),
      # * {#interval} ({Types::Int16le}),
      # * {#cap} ({Types::Int16le}).
      # @author Sylvain Daubert
      class Beacon < SubMngt
        # @!attribute timestamp
        #  @return [Integer] 64-bit timestamp
        define_field :timestamp, Types::Int64le
        # @!attribute interval
        #  @return [Integer] 16-bit interval value
        define_field :interval, Types::Int16le, default: 0x64
        # @!attribute cap
        #  @return [Integer] 16-bit capabillities word
        define_field :cap, Types::Int16le
      end
      Header.add_class Beacon
      Management.bind_header Beacon, op: :and, type: 0, subtype: 8

      # IEEE 802.11 ATIM frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 9.
      #
      # This class defines no field.
      # @author Sylvain Daubert
      class ATIM < SubMngt; end
      Header.add_class ATIM
      Management.bind_header ATIM, op: :and, type: 0, subtype: 9

      # IEEE 802.11 Disassociation frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 10.
      #
      # Add fields:
      # * {#reason} ({Types::Int16le}).
      # @author Sylvain Daubert
      class Disas < SubMngt
        # @!attribute reason
        #  @return [Integer] 16-bit reason value
        define_field :reason, Types::Int16le
      end
      Header.add_class Disas
      Management.bind_header Disas, op: :and, type: 0, subtype: 10

      # IEEE 802.11 Authentication frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 11.
      #
      # Add fields:
      # * {#algo} ({Types::Int16le}),
      # * {#seqnum} ({Types::Int16le}),
      # * {#status} ({Types::Int16le}).
      # @author Sylvain Daubert
      class Auth < SubMngt
        # @!attribute algo
        #  @return [Integer] 16-bit algo value
        define_field :algo, Types::Int16le
        # @!attribute seqnum
        #  @return [Integer] 16-bit seqnum value
        define_field :seqnum, Types::Int16le
        # @!attribute status
        #  @return [Integer] 16-bit status word
        define_field :status, Types::Int16le
      end
      Header.add_class Auth
      Management.bind_header Auth, op: :and, type: 0, subtype: 11

      # IEEE 802.11 Deauthentication frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 12.
      #
      # Add fields:
      # * {#reason} ({Types::Int16le}).
      # @author Sylvain Daubert
      class DeAuth < SubMngt
        # @!attribute reason
        #  @return [Integer] 16-bit reason value
        define_field :reason, Types::Int16le
      end
      Header.add_class DeAuth
      Management.bind_header DeAuth, op: :and, type: 0, subtype: 12
    end
  end
end
