# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class DNS
      # @!parse
      #  # DNS option is a TLV object:
      #  # * {#code} is a {Types::Int16},
      #  # * {#length #length} is a {Types::Int16},
      #  # * {#data} is a {Types::String}.
      #  #
      #  # @since 1.3.0
      #  # @since 3.1.0 defined with {Types::AbstractTLV}
      #  # @!parse class Option < Types::AbstractTLV; end
      #  # @!attribute code
      #  #   Alias for {#type}
      #  #   @return [Integer]
      #  # @!attribute data
      #  #   Alias for {#value}
      #  #   @return [Types::String]
      #  class Option < Types::AbstractTLV; end
      # @private
      Option = Types::AbstractTLV.create(type_class: Types::Int16,
                                         length_class: Types::Int16,
                                         aliases: { code: :type, data: :value })

      # Array of {Option}.
      # @since 3.1.1
      class ArrayOfOptions < Types::Array
        set_of Option
      end
    end
  end
end
