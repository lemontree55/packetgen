# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class SCTP
      # Common methods to Init and InitAck parameters
      # @author Sylvain Daubert
      module ParameterMixin
        include Padded32

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

      Parameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                            length_class: Types::Int16,
                                            field_in_length: 'TLV')
      # Base class/factory for {InitChunk} and {InitAckChunk} parameters
      # @author Sylvain Daubert
      class Parameter
        include ParameterMixin

        # Paramter Types
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

        # @return [::String]
        def to_human
          "<#{human_type}: #{self[:value].inspect}>"
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

      IPv4Parameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                length_class: Types::Int16,
                                                value_class: IP::Addr,
                                                field_in_length: 'TLV')

      # IPv4 address parameter
      # @author Sylvain Daubert
      class IPv4Parameter
        include ParameterMixin
      end
      IPv4Parameter.define_type_enum(Parameter::TYPES)
      IPv4Parameter.define_type_default('IPv4')

      IPv6Parameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                length_class: Types::Int16,
                                                value_class: IPv6::Addr,
                                                field_in_length: 'TLV')

      # IPv6 address parameter
      # @author Sylvain Daubert
      class IPv6Parameter
        include ParameterMixin
      end
      IPv6Parameter.define_type_enum(Parameter::TYPES)
      IPv6Parameter.define_type_default('IPv6')

      StateCookieParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                       length_class: Types::Int16,
                                                       value_class: Types::String,
                                                       field_in_length: 'TLV')

      # State Cookie parameter
      # @author Sylvain Daubert
      class StateCookieParameter
        include ParameterMixin

        # @return [::String]
        def to_human
          "<#{parameter_name}: #{self[:value].inspect}>"
        end
      end
      StateCookieParameter.define_type_enum(Parameter::TYPES)
      StateCookieParameter.define_type_default('StateCookie')

      UnrecognizedParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                        length_class: Types::Int16,
                                                        value_class: Parameter,
                                                        field_in_length: 'TLV')

      # Unrecognized parameter
      # @author Sylvain Daubert
      class UnrecognizedParameter
        include ParameterMixin

        # @return [::String]
        def to_human
          "<#{parameter_name}: #{self[:value].to_human}"
        end
      end
      UnrecognizedParameter.define_type_enum(Parameter::TYPES)
      UnrecognizedParameter.define_type_default('Unrecognized')

      HostnameParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                    length_class: Types::Int16,
                                                    value_class: Types::CString,
                                                    field_in_length: 'TLV')

      # Hostname address parameter
      # @author Sylvain Daubert
      class HostnameParameter
        include ParameterMixin
      end
      HostnameParameter.define_type_enum(Parameter::TYPES)
      HostnameParameter.define_type_default('Hostname')

      SupportedAddrTypesParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                              length_class: Types::Int16,
                                                              value_class: Types::ArrayOfInt16,
                                                              field_in_length: 'TLV')

      # Supported address types parameter
      # @author Sylvain Daubert
      class SupportedAddrTypesParameter
        include ParameterMixin

        # @return [::String]
        def to_human
          types = self[:value].map(&:to_i).map do |int16|
            Parameter::TYPES.key(int16) || int16.to_s
          end.join(',')
          "<#{parameter_name}: #{types}>"
        end
      end
      SupportedAddrTypesParameter.define_type_enum(Parameter::TYPES)
      SupportedAddrTypesParameter.define_type_default('SupportedAddrTypes')

      CookiePreservativeParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                              length_class: Types::Int16,
                                                              value_class: Types::Int32,
                                                              field_in_length: 'TLV')

      # Cookie Preservative parameter
      # @author Sylvain Daubert
      class CookiePreservativeParameter
        include ParameterMixin

        # @return [::String]
        def to_human
          "<#{parameter_name}: #{value}>"
        end
      end
      CookiePreservativeParameter.define_type_enum(Parameter::TYPES)
      CookiePreservativeParameter.define_type_default('CookiePreservative')

      ECNParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                               length_class: Types::Int16,
                                               field_in_length: 'TLV')

      # ECN parameter
      # @author Sylvain Daubert
      class ECNParameter
        include ParameterMixin

        # @return [::String]
        def to_human
          "<#{parameter_name}>"
        end
      end
      ECNParameter.define_type_enum(Parameter::TYPES)
      ECNParameter.define_type_default('ECN')

      HearbeatInfoParameter = Types::AbstractTLV.create(type_class: Types::Int16Enum,
                                                        length_class: Types::Int16,
                                                        field_in_length: 'TLV')

      # Heartbeat Information parameter
      # @author Sylvain Daubert
      class HearbeatInfoParameter
        include ParameterMixin
      end
      HearbeatInfoParameter.define_type_enum({ 'HearbeatInfo' => 1 }.freeze)
      HearbeatInfoParameter.define_type_default('HearbeatInfo')

      # Array of {Parameter}s and {ParameterMixin}.
      # @author Sylvain Daubert
      class ArrayOfParameter < Types::Array
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
