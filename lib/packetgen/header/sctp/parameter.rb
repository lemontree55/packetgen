# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class SCTP
      module ParameterMixin
        # Handle padding
        # @return [::String]
        def to_s
          s = super
          padlen = -(s.size % -4)
          s << force_binary("\x00" * padlen)
        end

        # Handle padding length
        # @return [Integer]
        def sz
          size = super
          size + (size % -4)
        end

        # Get parameter name
        # @return [String]
        def parameter_name
          self.class.name.split('::').last.delete_suffix('Parameter')
        end

        # @return [String]
        def to_human
          "<#{parameter_name}: #{value}>"
        end
      end

      # Base class/factory for {InitChunk} parameters
      Parameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                            length_class: Types::Int16,
                                            field_in_length: 'TLV')
      class Parameter
        # @private
        alias tlv_to_human to_human

        include ParameterMixin

        TYPES = {
          'IPv4' => 5,
          'IPv6' => 6,
          'StateCookie' => 7,
          'Unrecognized' => 8,
          'CookiePreservative' => 9,
          'Hostname' => 11,
          'SupportedAddrTypes' => 12,
          'ECN' => 32_768
        }.freeze

        # @return [String]
        def to_human
          "<#{tlv_to_human}>"
        end

        # @param [Object] value
        def from_human(value)
          if value.is_a?(self[:value].class)
            self[:value] = value
          else
            self[:value].from_human(value)
          end
        end
      end
      Parameter.define_type_enum(Parameter::TYPES)

      # IPv4 address parameter
      IPv4Parameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                length_class: Types::Int16,
                                                value_class: IP::Addr,
                                                field_in_length: 'TLV')

      class IPv4Parameter
        include ParameterMixin
      end
      IPv4Parameter.define_type_enum(Parameter::TYPES)

      # IPv6 address parameter
      IPv6Parameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                length_class: Types::Int16,
                                                value_class: IPv6::Addr,
                                                field_in_length: 'TLV')

      class IPv6Parameter
        include ParameterMixin
      end
      IPv6Parameter.define_type_enum(Parameter::TYPES)

      # State Cookie parameter
      StateCookieParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                       length_class: Types::Int16,
                                                       value_class: Types::String,
                                                       field_in_length: 'TLV')

      class StateCookieParameter
        include ParameterMixin

        def to_human
          "<#{parameter_name}: #{self[:value].inspect}>"
        end
      end
      StateCookieParameter.define_type_enum(Parameter::TYPES)

      # Unrecognized parameter
      UnrecognizedParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                        length_class: Types::Int16,
                                                        value_class: Parameter,
                                                        field_in_length: 'TLV')

      class UnrecognizedParameter
        include ParameterMixin

        def to_human
          "<#{parameter_name}: #{self[:value].to_human}"
        end
      end
      UnrecognizedParameter.define_type_enum(Parameter::TYPES)

      # Hostname address parameter
      HostnameParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                    length_class: Types::Int16,
                                                    value_class: Types::CString,
                                                    field_in_length: 'TLV')

      class HostnameParameter
        include ParameterMixin
      end
      HostnameParameter.define_type_enum(Parameter::TYPES)

      # Supported address types parameter
      SupportedAddrTypesParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                              length_class: Types::Int16,
                                                              value_class: Types::ArrayOfInt16,
                                                              field_in_length: 'TLV')

      class SupportedAddrTypesParameter
        include ParameterMixin

        def to_human
          types = self[:value].map(&:to_i).map do |int16|
            Parameter::TYPES.key(int16) || int16.to_s
          end.join(',')
          "<#{parameter_name}: #{types}>"
        end
      end
      SupportedAddrTypesParameter.define_type_enum(Parameter::TYPES)

      # Cookie Preservative parameter
      CookiePreservativeParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                              length_class: Types::Int16,
                                                              value_class: Types::Int32,
                                                              field_in_length: 'TLV')

      class CookiePreservativeParameter
        include ParameterMixin

        def to_human
          "<#{parameter_name}: #{value}>"
        end
      end
      CookiePreservativeParameter.define_type_enum(Parameter::TYPES)

      # ECN parameter
      ECNParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                               length_class: Types::Int16,
                                               field_in_length: 'TLV')

      class ECNParameter
        include ParameterMixin

        def to_human
          "<#{parameter_name}>"
        end
      end
      ECNParameter.define_type_enum(Parameter::TYPES)

      # Heartbeat Information parameter
      HearbeatInfoParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                        length_class: Types::Int16,
                                                        field_in_length: 'TLV')

      class HearbeatInfoParameter
        include ParameterMixin
      end
      HearbeatInfoParameter.define_type_enum({ 'HearbeatInfo' => 1 }.freeze)

      class ArrayOfParameters < Types::Array
        set_of Parameter

        private

        # Get real type from {Parameter} type
        def real_type(param)
          type_name = Parameter::TYPES.key(param.type)
          return param.class if type_name.nil?

          SCTP.const_get(real_klass_name(type_name)) || param.class
        end

        def real_klass_name(type_name)
          type_name + 'Parameter' # rubocop:disable Style/StringConcatenation
        end
      end
    end
  end
end
