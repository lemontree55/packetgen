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
    # * a {#dsap} ({Types::Int8}),
    # * a {#ssap} ({Types::Int8}),
    # * a {#control} ({Types::Int8}),
    # * and a {#body} (a {Types::String} or another {Base} class).
    # @author Sylvain Daubert
    # @since 1.4.0
    class LLC < Base
      # @!attribute dsap
      #  @return [Integer] 8-bit dsap value
      define_field :dsap, Types::Int8
      # @!attribute ssap
      #  @return [Integer] 8-bit ssap value
      define_field :ssap, Types::Int8
      # @!attribute control
      #  @return [Integer] 8-bit control value
      define_field :control, Types::Int8
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String
    end
    self.add_class LLC
    Dot11::Data.bind LLC, type: 2, wep?: false

    # Sub-Network Access Protocol
    #
    # A SNAP header consists of:
    # * a {#oui} ({Types::OUI}),
    # * a {#proto_id} ({Types::Int16}),
    # * and a {#body} (a {Types::String} or another {Base} class).
    # @author Sylvain Daubert
    # @since 1.4.0
    class SNAP < Base
      # @!attribute oui
      #  @return [Types::OUI]
      define_field :oui, Types::OUI
      # @!attribute proto_id
      #  @return [Integer] 16-bit protocol id
      define_field :proto_id, Types::Int16
      # @!attribute body
      #  @return [Types::String,Header::Base]
      define_field :body, Types::String
    end
    self.add_class SNAP
    LLC.bind SNAP, dsap: 170, ssap: 170, control: 3
  end
end
