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
      #  # Base class/factory for {AbortChunk} and {ErrorChunk} error causes
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 No more include +ErrorMixin+
      #  class Error < BinStruct::AbstractTLV; end
      Error = BinStruct::AbstractTLV.create(type_class: BinStruct::Int16Enum,
                                            length_class: BinStruct::Int16,
                                            attr_in_length: 'TLV')

      class Error
        include Padded32

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

        # Get error name
        # @return [String]
        def error_name
          self.class.name.split('::').last.delete_suffix('Error')
        end

        # Get human-readable description
        # @return [String]
        def to_human
          "<#{error_name}: #{value}>"
        end

        # Set +#value+ from +value+
        # @param [Object] value
        # @return self
        def from_human(value)
          if value.is_a?(self[:value].class)
            self[:value] = value
          else
            self[:value].from_human(value)
          end
          self
        end
      end
      Error.define_type_enum(Error::TYPES)

      # Handle array of {Error} classes.
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
          type_name + 'Error'
        end
      end

      # @!parse
      #  # Base class for error without value.
      #  # @author LemonTree55
      #  # @since 4.1.0 Derived from {Error}
      #  class NoValueError < Error; end
      NoValueError = Error.derive

      class NoValueError
        # Get human-readable string
        # @return [String]
        def to_human
          "<#{error_name}>"
        end
      end

      # @!parse
      #  # InvalidStreamIdentifier error
      #  # @author Sylvain Daubert
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class InvalidStreamIdError < Error; end
      InvalidStreamIdError = Error.derive(value_class: BinStruct::Int32)
      InvalidStreamIdError.define_type_default('InvalidStreamId')

      class InvalidStreamIdError
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

        # Get human-readable string
        # @return [String]
        def to_human
          "<#{error_name}: #{stream_identifier}>"
        end

        # Set +#value+ from an Integer
        # @param [Integer] val
        def from_human(val)
          super
          self.value <<= 16 if self[:value] < BinStruct::Int
        end
      end

      # @!parse
      #  # MissingMandatoryParameter error. Indicate that one or more
      #  # mandatory TLV parameters are missing in a received {InitChunk}
      #  # or {InitAckChunk}.
      #  # @author Sylvain Daubert
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class MissingMandatoryParameterError < Error; end
      MissingMandatoryParameterError = Error.derive(value_class: BinStruct::ArrayOfInt16)
      MissingMandatoryParameterError.define_type_default('MissingMandatoryParameter')

      class MissingMandatoryParameterError
        # Get human-readable string
        # @return [String]
        def to_human
          "<#{error_name}: #{self[:value].to_human}>"
        end
      end

      # @!parse
      #  # StaleCookie error. Indicates the receipt of a valid State Cookie that
      #  # has expired.
      #  # @author Sylvain Daubert
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class StaleCookieError < Error; end
      StaleCookieError = Error.derive(value_class: BinStruct::Int32)
      StaleCookieError.define_type_default('StaleCookie')

      # @!parse
      #  # Out of ressource error. Indicates that the sender is out of resource.
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class OutOfResourceError < NoValueError; end
      OutOfResourceError = NoValueError.derive
      OutOfResourceError.define_type_default('OutOfResource')

      # @!parse
      #  # Unresolvable address error. Indicates that the sender is not able to resolve the specified
      #  # address parameter (type of address is not supported)
      #  # @author Sylvain Daubert
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class UnresolvableAddressError < Error; end
      UnresolvableAddressError = Error.derive(value_class: Parameter)
      UnresolvableAddressError.define_type_default('UnresolvableAddress')

      class UnresolvableAddressError
        # Set +value+ by accepting {Parameter} classes.
        # @param [Parameter] val
        # @return [Parameter]
        def value=(val)
          if val.is_a?(Parameter)
            self[:value] = val
            calc_length
            val
          else
            super
          end
        end

        # Get human-readable string
        # @return [String]
        def to_human
          "<#{error_name}: #{self[:value].to_human}>"
        end
      end

      # @!parse
      #  # Unrecognized chunk type error. The receiver does not understand the chunk and the upper bits of the 'Chunk Type'
      #  # are set to 01 or 11.
      #  # @author Sylvain Daubert
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class UnrecognizedChunkTypeError < Error; end
      UnrecognizedChunkTypeError = Error.derive(value_class: BaseChunk)
      UnrecognizedChunkTypeError.define_type_default('UnrecognizedChunkType')

      class UnrecognizedChunkTypeError
        # Get human-readable string
        # @return [String]
        def to_human
          "<#{error_name}: #{self[:value].to_human}>"
        end
      end

      # @!parse
      #  # Invalid mandatory parameter error. Returned to the originator of an INIT or INIT ACK chunk when one of the
      #  # mandatory parameters is set to an invalid value.
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class InvalidMandatoryParameterError < NoValueError; end
      InvalidMandatoryParameterError = NoValueError.derive
      InvalidMandatoryParameterError.define_type_default('InvalidMandatoryParameter')

      # @!parse
      #  # Unrecognized parameters error. Returned to the originator of the INIT ACK chunk if the receiver does not
      #  # recognize one or more Optional TLV parameters in the INIT ACK chunk.
      #  # @author Sylvain Daubert
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class UnrecognizedParametersError < Error; end
      UnrecognizedParametersError = Error.derive(value_class: ArrayOfParameter)
      UnrecognizedParametersError.define_type_default('UnrecognizedParameters')

      class UnrecognizedParametersError
        # Get human-readable string
        # @return [String]
        def to_human
          "<#{error_name}: #{self[:value].to_human}>"
        end
      end

      # @!parse
      #  # No user data error. Returned when a received {DataChunk} was received with no data.
      #  # @author Sylvain Daubert
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class NoUserDataError < Error; end
      NoUserDataError = Error.derive(value_class: BinStruct::Int32)
      NoUserDataError.define_type_default('NoUserData')

      # @!parse
      #  # Cookie received while shutting down error.
      #  # A COOKIE ECHO chunk was received while the endpoint was in the SHUTDOWN-ACK-SENT state.
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class CookieReceivedWhileShuttingDownError < NoValueError; end
      CookieReceivedWhileShuttingDownError = NoValueError.derive
      CookieReceivedWhileShuttingDownError.define_type_default('CookieReceivedWhileShuttingDown')

      # @!parse
      #  # INIT added an address out of association.
      #  # @author Sylvain Daubert
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class RestartAssociationWithNewAddressError < Error; end
      RestartAssociationWithNewAddressError = Error.derive(value_class: ArrayOfParameter)
      RestartAssociationWithNewAddressError.define_type_default('RestartAssociationWithNewAddress')

      class RestartAssociationWithNewAddressError
        # Get human-readable string
        # @return [String]
        def to_human
          "<#{error_name}: #{self[:value].to_human}>"
        end
      end

      # @!parse
      #  # User-Initiated abort error.
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class UserInitiatedAbortError < NoValueError; end
      UserInitiatedAbortError = NoValueError.derive
      UserInitiatedAbortError.define_type_default('UserInitiatedAbort')

      # @!parse
      #  # User-Initiated abort error.
      #  # @author LemonTree55
      #  # @since 3.4.0
      #  # @since 4.1.0 Derived from {Error}
      #  class ProtocolViolationError < NoValueError; end
      ProtocolViolationError = NoValueError.derive
      ProtocolViolationError.define_type_default('ProtocolViolation')
    end
  end
end
