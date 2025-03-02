# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class SCTP
      # @!parse
      #   class Parameter < BinStruct::AbstractTLV; end
      Parameter = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                length_class: BinStruct::Int16,
                                                attr_in_length: 'TLV')
      # Base class/factory for {InitChunk} and {InitAckChunk} parameters
      # @author Sylvain Daubert
      # @author LemonTree55
      # @since 3.4.0
      # @since 4.1.0 No more include +ParamterMixin+.
      class Parameter
        include Padded32

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

        # Get human-readable descriptiob
        # @return [::String]
        def to_human
          value = if self[:value].is_a?(BinStruct::String)
                    self[:value].inspect
                  else
                    self[:value].to_human
                  end
          "<#{human_type}: #{value}>"
        end

        # Populate parameter from a human-readable string or a Parameter.
        # @param [Parameter,String] value
        def from_human(value)
          if value.is_a?(self[:value].class)
            self[:value] = value
          else
            self[:value].from_human(value)
          end
        end

        # Get parameter name
        # @return [String]
        def parameter_name
          self.class.name.split('::').last.delete_suffix('Parameter')
        end
      end
      Parameter.define_type_enum(Parameter::TYPES)

      # @!parse
      #   # IPv4 address parameter. A {Parameter} whose value is a {IP::Addr}.
      #   # @author Sylvain Daubert
      #   # @author LemonTree55
      #   # @since 3.4.0
      #   # @since 4.1.0 Subclass of {Parameter}. No more include +ParameterMixin+.
      #   class IPv4Parameter < Parameter; end
      IPv4Parameter = Parameter.derive(value_class: IP::Addr)
      IPv4Parameter.define_type_default('IPv4')

      # @!parse
      #   # IPv6 address parameter. A {Parameter} whose value is a {IPv6::Addr}.
      #   # @author Sylvain Daubert
      #   # @author LemonTree55
      #   # @since 3.4.0
      #   # @since 4.1.0 Subclass of {Parameter}. No more include +ParameterMixin+.
      #   class IPv6Parameter < Parameter; end
      IPv6Parameter = Parameter.derive(value_class: IPv6::Addr)
      IPv6Parameter.define_type_default('IPv6')

      # State Cookie parameter. A {Parameter} whose value is a cookie string.
      # @author Sylvain Daubert
      # @author LemonTree55
      # @since 3.4.0
      # @since 4.1.0 Subclass of {Parameter}. No more include +ParameterMixin+.
      class StateCookieParameter < Parameter
      end
      StateCookieParameter.define_type_default('StateCookie')

      # @!parse
      #   # Unrecognized parameter. A {Parameter} whose value is a {Parameter}.
      #   # @author Sylvain Daubert
      #   # @author LemonTree55
      #   # @since 3.4.0
      #   # @since 4.1.0 Subclass of {Parameter}. No more include +ParameterMixin+.
      #   class UnrecognizedParameter < Parameter; end
      UnrecognizedParameter = Parameter.derive(value_class: Parameter)
      UnrecognizedParameter.define_type_default('Unrecognized')

      # @!parse
      #   # Hostname address parameter. A {Parameter} whose value is a null-terminated string.
      #   # @author Sylvain Daubert
      #   # @author LemonTree55
      #   # @since 3.4.0
      #   # @since 4.1.0 Subclass of {Parameter}. No more include +ParameterMixin+.
      #   class HostnameParameter < Parameter; end
      HostnameParameter = Parameter.derive(value_class: BinStruct::CString)
      HostnameParameter.define_type_default('Hostname')

      # @!parse
      #   # Supported address types parameter. æ {Parameter} whose value is an array of supported address types
      #   # (as +BinStruct::Int16+).
      #   # @author Sylvain Daubert
      #   # @author LemonTree55
      #   # @since 3.4.0
      #   # @since 4.1.0 Subclass of {Parameter}. No more include +ParameterMixin+.
      #   class SupportedAddrTypesParameter < Parameter; end
      SupportedAddrTypesParameter = Parameter.derive(value_class: BinStruct::ArrayOfInt16)
      SupportedAddrTypesParameter.define_type_default('SupportedAddrTypes')

      class SupportedAddrTypesParameter
        # Get human-readable description
        # @return [::String]
        def to_human
          types = self[:value].map(&:to_i).map do |int16|
            Parameter::TYPES.key(int16) || int16.to_s
          end.join(',')
          "<#{parameter_name}: #{types}>"
        end
      end

      # @!parse
      #   # Cookie preservative parameter. A {Parameter} whose value is a +BinStruct::Int32+.
      #   # @author Sylvain Daubert
      #   # @author LemonTree55
      #   # @since 3.4.0
      #   # @since 4.1.0 Subclass of {Parameter}. No more include +ParameterMixin+.
      #   class CookiePreservativeParameter < Parameter; end
      CookiePreservativeParameter = Parameter.derive(value_class: BinStruct::Int32)
      CookiePreservativeParameter.define_type_default('CookiePreservative')

      # ECN parameter. A {Parameter} who has no value.
      # @author Sylvain Daubert
      # @author LemonTree55
      # @since 3.4.0
      # @since 4.1.0 Subclass of {Parameter}. No more include +ParameterMixin+.
      class ECNParameter < Parameter
        # Get human readable description
        # @return [::String]
        def to_human
          "<#{parameter_name}>"
        end
      end
      ECNParameter.define_type_default('ECN')

      # Array of {Parameter parameters}.
      # @author Sylvain Daubert
      class ArrayOfParameter < BinStruct::Array
        set_of Parameter

        private

        # Get real type from {Parameter} type
        def real_type(param)
          type_name = Parameter::TYPES.key(param.type)
          return param.class if type_name.nil?

          SCTP.const_get(real_klass_name(type_name)) || param.class
        end

        def real_klass_name(type_name)
          "#{type_name}Parameter"
        end
      end
    end
  end
end
