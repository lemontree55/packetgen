# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # Logical-Link Control header
    #
    # A LLC header consists of:
    # * a {#dsap} (+BinStruct::Int8+),
    # * a {#ssap} (+BinStruct::Int8+),
    # * a {#control} (+BinStruct::Int8+),
    # * and a {#body} (a +BinStruct::String+ or another {Headerable} class).
    # @author Sylvain Daubert
    # @since 1.4.0
    class LLC < Base
      # @!attribute dsap
      #  8-bit Destination Service Access Point value
      #  @return [Integer]
      define_attr :dsap, BinStruct::Int8
      # @!attribute ssap
      #  8-bit Source Service Access Point value
      #  @return [Integer]
      define_attr :ssap, BinStruct::Int8
      # @!attribute control
      #  8-bit control value
      #  @return [Integer]
      define_attr :control, BinStruct::Int8
      # @!attribute body
      #  LLC body
      #  @return [BinStruct::String,Headerable]
      define_attr :body, BinStruct::String
    end
    self.add_class LLC
    Dot11::Data.bind LLC, type: 2, wep?: false

    # Sub-Network Access Protocol
    #
    # A SNAP header consists of:
    # * a {#oui} (+BinStruct::OUI+),
    # * a {#proto_id} (+BinStruct::Int16+),
    # * and a {#body} (a +BinStruct::String+ or another {Headerable} class).
    # @author Sylvain Daubert
    # @since 1.4.0
    class SNAP < Base
      # @!attribute oui
      #  If +00:00:00+, {#proto_id} is an EtherType. Else, {#proto_id} is specified by organization specified BY +OUI+.
      #  @return [BinStruct::OUI]
      define_attr :oui, BinStruct::OUI
      # @!attribute proto_id
      #  16-bit protocol id
      #  @return [Integer]
      define_attr :proto_id, BinStruct::Int16
      # @!attribute body
      #  SNAP header
      #  @return [BinStruct::String,Headerable]
      define_attr :body, BinStruct::String
    end
    self.add_class SNAP
    LLC.bind SNAP, dsap: 170, ssap: 170, control: 3
  end
end
