# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
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
        define_attr :elements, ArrayOfElements
      end

      # IEEE 802.11 Association Request frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 0.
      #
      # Add fields:
      # * {#cap} ({BinStruct::Int16le}),
      # * {#listen_interval} ({BinStruct::Int16le}).
      # @author Sylvain Daubert
      class AssoReq < SubMngt
        # @!attribute cap
        #  @return [Integer] 16-bit capabillities word
        define_attr_before :elements, :cap, BinStruct::Int16le
        # @!attribute listen_interval
        #  @return [Integer] 16-bit listen interval value
        define_attr_before :elements, :listen_interval, BinStruct::Int16le, default: 0x00c8
      end
      Header.add_class AssoReq
      Management.bind AssoReq, type: 0, subtype: 0

      # IEEE 802.11 Association Response frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 1.
      #
      # Add fields:
      # * {#cap} ({BinStruct::Int16le}),
      # * {#status} ({BinStruct::Int16le}),
      # * {#aid} ({BinStruct::Int16le}).
      # @author Sylvain Daubert
      class AssoResp < SubMngt
        # @!attribute cap
        #  @return [Integer] 16-bit capabillities word
        define_attr_before :elements, :cap, BinStruct::Int16le
        # @!attribute status
        #  @return [Integer] 16-bit status word
        define_attr_before :elements, :status, BinStruct::Int16le
        # @!attribute aid
        #  @return [Integer] 16-bit AID word
        define_attr_before :elements, :aid, BinStruct::Int16le
      end
      Header.add_class AssoResp
      Management.bind AssoResp, type: 0, subtype: 1

      # IEEE 802.11 ReAssociation Request frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 2.
      #
      # Add fields:
      # * {#cap} ({BinStruct::Int16le}),
      # * {#listen_interval} ({BinStruct::Int16le}),
      # * {#current_ap} ({Eth::MacAddr}).
      # @author Sylvain Daubert
      class ReAssoReq < AssoReq
        # @!attribute current_ap
        #  @return [Eth::MAcAddr]
        define_attr_before :elements, :current_ap, Eth::MacAddr
      end
      Header.add_class ReAssoReq
      Management.bind ReAssoReq, type: 0, subtype: 2

      # IEEE 802.11 ReAssociation Response frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 3.
      #
      # Add fields:
      # * {#cap} ({BinStruct::Int16le}),
      # * {#status} ({BinStruct::Int16le}),
      # * {#aid} ({BinStruct::Int16le}).
      # @author Sylvain Daubert
      class ReAssoResp < AssoResp
      end
      Header.add_class ReAssoResp
      Management.bind ReAssoResp, type: 0, subtype: 3

      # IEEE 802.11 Probe Request frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 4.
      #
      # This class adds no field.
      # @author Sylvain Daubert
      class ProbeReq < SubMngt
      end
      Header.add_class ProbeReq
      Management.bind ProbeReq, type: 0, subtype: 4

      # IEEE 802.11 Probe Response frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 5.
      #
      # Add fields:
      # * {#timestamp} ({BinStruct::Int64le}),
      # * {#beacon_interval} ({BinStruct::Int16le}),
      # * {#cap} ({BinStruct::Int16le}).
      # @author Sylvain Daubert
      class ProbeResp < SubMngt
        # @!attribute timestamp
        #  @return [Integer] 64-bit timestamp
        define_attr_before :elements, :timestamp, BinStruct::Int64le
        # @!attribute beacon_interval
        #  @return [Integer] 16-bit beacon interval value
        define_attr_before :elements, :beacon_interval, BinStruct::Int16le, default: 0x0064
        # @!attribute cap
        #  @return [Integer] 16-bit capabillities word
        define_attr_before :elements, :cap, BinStruct::Int16le
      end
      Header.add_class ProbeResp
      Management.bind ProbeResp, type: 0, subtype: 5

      # IEEE 802.11 Beacon frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 8.
      #
      # Add fields:
      # * {#timestamp} ({BinStruct::Int64le}),
      # * {#interval} ({BinStruct::Int16le}),
      # * {#cap} ({BinStruct::Int16le}).
      # @author Sylvain Daubert
      class Beacon < SubMngt
        # @!attribute timestamp
        #  @return [Integer] 64-bit timestamp
        define_attr_before :elements, :timestamp, BinStruct::Int64le
        # @!attribute interval
        #  @return [Integer] 16-bit interval value
        define_attr_before :elements, :interval, BinStruct::Int16le, default: 0x64
        # @!attribute cap
        #  @return [Integer] 16-bit capabillities word
        define_attr_before :elements, :cap, BinStruct::Int16le
      end
      Header.add_class Beacon
      Management.bind Beacon, type: 0, subtype: 8

      # IEEE 802.11 ATIM frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 9.
      #
      # This class defines no field.
      # @author Sylvain Daubert
      class ATIM < SubMngt; end
      Header.add_class ATIM
      Management.bind ATIM, type: 0, subtype: 9

      # IEEE 802.11 Disassociation frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 10.
      #
      # Add fields:
      # * {#reason} ({BinStruct::Int16le}).
      # @author Sylvain Daubert
      class Disas < SubMngt
        # @!attribute reason
        #  @return [Integer] 16-bit reason value
        define_attr_before :elements, :reason, BinStruct::Int16le
      end
      Header.add_class Disas
      Management.bind Disas, type: 0, subtype: 10

      # IEEE 802.11 Authentication frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 11.
      #
      # Add fields:
      # * {#algo} ({BinStruct::Int16le}),
      # * {#seqnum} ({BinStruct::Int16le}),
      # * {#status} ({BinStruct::Int16le}).
      # @author Sylvain Daubert
      class Auth < SubMngt
        # @!attribute algo
        #  @return [Integer] 16-bit algo value
        define_attr_before :elements, :algo, BinStruct::Int16le
        # @!attribute seqnum
        #  @return [Integer] 16-bit seqnum value
        define_attr_before :elements, :seqnum, BinStruct::Int16le
        # @!attribute status
        #  @return [Integer] 16-bit status word
        define_attr_before :elements, :status, BinStruct::Int16le
      end
      Header.add_class Auth
      Management.bind Auth, type: 0, subtype: 11

      # IEEE 802.11 Deauthentication frame
      #
      # Specialize {Dot11::Management} with +subtype+ set to 12.
      #
      # Add fields:
      # * {#reason} ({BinStruct::Int16le}).
      # @author Sylvain Daubert
      class DeAuth < SubMngt
        # @!attribute reason
        #  @return [Integer] 16-bit reason value
        define_attr_before :elements, :reason, BinStruct::Int16le
      end
      Header.add_class DeAuth
      Management.bind DeAuth, type: 0, subtype: 12
    end
  end
end
