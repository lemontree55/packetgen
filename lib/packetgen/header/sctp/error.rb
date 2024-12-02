# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class SCTP
      # Common methods to all error causes
      # @author Sylvain Daubert
      module ErrorMixin
        include Padded32

        # Get error name
        # @return [String]
        def error_name
          self.class.name.split('::').last.delete_suffix('Error')
        end

        # @return [String]
        def to_human
          "<#{error_name}: #{value}>"
        end
      end

      Error = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                            length_class: BinStruct::Int16,
                                            attr_in_length: 'TLV')

      # Base class/factory for {AbortChunk} and {ErrorChunk} error causes
      # @author Sylvain Daubert
      class Error
        include ErrorMixin

        # Error Causes/Types
        TYPES = {
          'InvalidStreamId' => 1,
          'MissingMandatoryParameter' => 2,
          'StaleCookie' => 3,
          'OutOfResource' => 4,
          'UnresolvableAddress' => 5,
          'UnrecognizedChunkType' => 6,
          'InvalidMandatoryParameter' => 7,
          'UnrecognizedParameters' => 8,
          'NoUserData' => 9,
          'CookieReceivedWhileShuttingDown' => 10,
          'RestartAssociationWithNewAddress' => 11,
          'UserInitiatedAbort' => 12,
          'ProtocolViolation' => 13
        }.freeze

        # @param [Object] value
        def from_human(value)
          if value.is_a?(self[:value].class)
            self[:value] = value
          else
            self[:value].from_human(value)
          end
        end
      end
      Error.define_type_enum(Error::TYPES)

      # Handle array of {Error} and {ErrorMixin} classes.
      # @author Sylvain Daubert
      class ArrayOfError < BinStruct::Array
        set_of Error

        private

        # @param [Error,ErrorMixin] error
        def real_type(error)
          type_name = Error::TYPES.key(error.type)
          return error.class if type_name.nil?

          SCTP.const_get(real_klass_name(type_name)) || error.class
        end

        def real_klass_name(type_name)
          type_name + 'Error' # rubocop:disable Style/StringConcatenation
        end
      end

      InvalidStreamIdError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                           length_class: BinStruct::Int16,
                                                           value_class: BinStruct::Int32,
                                                           attr_in_length: 'TLV')

      # InvalidStreamIdentifier error
      # @author Sylvain Daubert
      class InvalidStreamIdError
        include ErrorMixin

        # Get stream Id value
        # @return [Integer]
        def stream_identifier
          self.value >> 16
        end

        # Set stream Id value
        # @param [Integer] stream_id
        # @return [Integer]
        def stream_identifier=(stream_id)
          self.value = (stream_id & 0xffff) << 16
          stream_id
        end

        # @return [::String]
        def to_human
          "<#{error_name}: #{stream_identifier}>"
        end

        # @param [Integer] val
        def from_human(val)
          super
          self.value <<= 16 if self[:value] < BinStruct::Int
        end
      end
      InvalidStreamIdError.define_type_enum(Error::TYPES)
      InvalidStreamIdError.define_type_default('InvalidStreamId')

      MissingMandatoryParameterError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                                     length_class: BinStruct::Int16,
                                                                     value_class: BinStruct::ArrayOfInt16,
                                                                     attr_in_length: 'TLV')

      # MissingMandatoryParameter error. Indicate that one or more
      # mandatory TLV parameters are missing in a received {InitChunk}
      # or {InitAckChunk}.
      # @author Sylvain Daubert
      class MissingMandatoryParameterError
        include ErrorMixin

        # @return [::String]
        def to_human
          "<#{error_name}: #{self[:value].to_human}>"
        end
      end
      MissingMandatoryParameterError.define_type_enum(Error::TYPES)
      MissingMandatoryParameterError.define_type_default('MissingMandatoryParameter')

      StaleCookieError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                       length_class: BinStruct::Int16,
                                                       value_class: BinStruct::Int32,
                                                       attr_in_length: 'TLV')

      # StaleCookie error. Indicates the receipt of a valid State Cookie that
      # has expired.
      # @author Sylvain Daubert
      class StaleCookieError
        include ErrorMixin
      end
      StaleCookieError.define_type_enum(Error::TYPES)
      StaleCookieError.define_type_default('StaleCookie')

      OutOfResourceError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                         length_class: BinStruct::Int16,
                                                         attr_in_length: 'TLV')

      # Out of ressource error. Indicates that the sender is out of resource.
      # @author Sylvain Daubert
      class OutOfResourceError
        include ErrorMixin

        # @return [::String]
        def to_human
          "<#{error_name}>"
        end
      end
      OutOfResourceError.define_type_enum(Error::TYPES)
      OutOfResourceError.define_type_default('OutOfResource')

      UnresolvableAddressError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                               length_class: BinStruct::Int16,
                                                               value_class: Parameter,
                                                               attr_in_length: 'TLV')

      # Out of ressource error. Indicates that the sender is out of resource.
      # @author Sylvain Daubert
      class UnresolvableAddressError
        include ErrorMixin

        # Set +value+ by accepting {ParameterMixin} classes.
        # @param [ParameterMixin] val
        # @return [ParameterMixin]
        def value=(val)
          if val.is_a?(ParameterMixin)
            self[:value] = val
            calc_length
            val
          else
            super
          end
        end

        # @return [::String]
        def to_human
          "<#{error_name}: #{self[:value].to_human}>"
        end
      end
      UnresolvableAddressError.define_type_enum(Error::TYPES)
      UnresolvableAddressError.define_type_default('UnresolvableAddress')

      UnrecognizedChunkTypeError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                                 length_class: BinStruct::Int16,
                                                                 value_class: BaseChunk,
                                                                 attr_in_length: 'TLV')

      # Unrecognized chunk type error. The receiver does not understand the chunk and the upper bits of the 'Chunk Type'
      # are set to 01 or 11.
      # @author Sylvain Daubert
      class UnrecognizedChunkTypeError
        include ErrorMixin

        # @return [::String]
        def to_human
          "<#{error_name}: #{self[:value].to_human}>"
        end
      end
      UnrecognizedChunkTypeError.define_type_enum(Error::TYPES)
      UnrecognizedChunkTypeError.define_type_default('UnrecognizedChunkType')

      InvalidMandatoryParameterError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                                     length_class: BinStruct::Int16,
                                                                     attr_in_length: 'TLV')

      # Invalid mandatory parameter error. Returned to the originator of an INIT or INIT ACK chunk when one of the
      # mandatory parameters is set to an invalid value.
      # @author Sylvain Daubert
      class InvalidMandatoryParameterError
        include ErrorMixin

        # @return [::String]
        def to_human
          "<#{error_name}>"
        end
      end
      InvalidMandatoryParameterError.define_type_enum(Error::TYPES)
      InvalidMandatoryParameterError.define_type_default('InvalidMandatoryParameter')

      UnrecognizedParametersError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                                  length_class: BinStruct::Int16,
                                                                  value_class: ArrayOfParameter,
                                                                  attr_in_length: 'TLV')

      # Unrecognized parameters error. Returned to the originator of the INIT ACK chunk if the receiver does not
      # recognize one or more Optional TLV parameters in the INIT ACK chunk.
      # @author Sylvain Daubert
      class UnrecognizedParametersError
        include ErrorMixin

        # @return [::String]
        def to_human
          "<#{error_name}: #{self[:value].to_human}>"
        end
      end
      UnrecognizedParametersError.define_type_enum(Error::TYPES)
      UnrecognizedParametersError.define_type_default('UnrecognizedParameters')

      NoUserDataError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                      length_class: BinStruct::Int16,
                                                      value_class: BinStruct::Int32,
                                                      attr_in_length: 'TLV')

      # No user data error. Returned when a received {DataChunk} was received with no data.
      # @author Sylvain Daubert
      class NoUserDataError
        include ErrorMixin
      end
      NoUserDataError.define_type_enum(Error::TYPES)
      NoUserDataError.define_type_default('NoUserData')

      CookieReceivedWhileShuttingDownError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                                           length_class: BinStruct::Int16,
                                                                           attr_in_length: 'TLV')

      # Cookie received while shutting down error.
      # A COOKIE ECHO chunk was received while the endpoint was in the SHUTDOWN-ACK-SENT state.
      # @author Sylvain Daubert
      class CookieReceivedWhileShuttingDownError
        include ErrorMixin

        # @return [::String]
        def to_human
          "<#{error_name}>"
        end
      end
      CookieReceivedWhileShuttingDownError.define_type_enum(Error::TYPES)
      CookieReceivedWhileShuttingDownError.define_type_default('CookieReceivedWhileShuttingDown')

      RestartAssociationWithNewAddressError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                                            length_class: BinStruct::Int16,
                                                                            value_class: ArrayOfParameter,
                                                                            attr_in_length: 'TLV')

      # Cookie received while shutting down error.
      # A COOKIE ECHO chunk was received while the endpoint was in the SHUTDOWN-ACK-SENT state.
      # @author Sylvain Daubert
      class RestartAssociationWithNewAddressError
        include ErrorMixin

        # @return [::String]
        def to_human
          "<#{error_name}: #{self[:value].to_human}>"
        end
      end
      RestartAssociationWithNewAddressError.define_type_enum(Error::TYPES)
      RestartAssociationWithNewAddressError.define_type_default('RestartAssociationWithNewAddress')

      UserInitiatedAbortError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                              length_class: BinStruct::Int16,
                                                              attr_in_length: 'TLV')

      # User-Initiated abort error.
      # @author Sylvain Daubert
      class UserInitiatedAbortError
        include ErrorMixin

        # @return [::String]
        def to_human
          "<#{error_name}>"
        end
      end
      UserInitiatedAbortError.define_type_enum(Error::TYPES)
      UserInitiatedAbortError.define_type_default('UserInitiatedAbort')

      ProtocolViolationError = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                                             length_class: BinStruct::Int16,
                                                             attr_in_length: 'TLV')

      # Protocol violation error.
      # @author Sylvain Daubert
      class ProtocolViolationError
        include ErrorMixin

        # @return [::String]
        def to_human
          "<#{error_name}>"
        end
      end
      ProtocolViolationError.define_type_enum(Error::TYPES)
      ProtocolViolationError.define_type_default('ProtocolViolation')
    end
  end
end
