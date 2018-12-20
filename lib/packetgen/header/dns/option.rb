# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class DNS
      # DNS option
      Option = Types::AbstractTLV.create(type_class: Types::Int16,
                                         length_class: Types::Int16)

      class Option
        # Same as TLV#initialize but add some facilities.
        # @param [Hash] options
        # @option [String,Integer] :code same as +:type+
        # @option [String,Integer] :data same as +:value+
        def initialize(options={})
          options[:type] = options[:code] unless options.key? :type
          options[:value] = options[:data] unless options.key? :value
          super
        end

        alias code type
        alias code= type=
        alias data value
        alias data= value=
      end

      # Array of {Option}.
      # @since 3.1.1
      class ArrayOfOptions < Types::Array
        set_of Option
      end
    end
  end
end
