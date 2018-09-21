# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class SMB
      # Transaction Request.
      #
      # See also {Blocks}, as {Trans} is a specialization of {Blocks#words}
      # and {Blocks#bytes}.
      # @author Sylvain Daubert
      class TransRequest < Base
        # @!attribute word_count
        #  The size, in 2-byte words, of the SMB command parameters. It should
        #  be +14 + setup_count+.
        #  @return [Integer]
        define_field :word_count, Types::Int8, default: 14
        # @!attribute total_param_count
        #  The total number of transaction parameter bytes.
        #  @return [Integer]
        define_field :total_param_count, Types::Int16le
        # @!attribute total_data_count
        #  The total number of transaction data bytes.
        #  @return [Integer]
        define_field :total_data_count, Types::Int16le
        # @!attribute max_param_count
        #  The maximum number of parameter bytes that the client will accept
        #  in transaction response.
        #  @return [Integer]
        define_field :max_param_count, Types::Int16le
        # @!attribute max_data_count
        #  The maximum number of data bytes that the client will accept
        #  in transaction response.
        #  @return [Integer]
        define_field :max_data_count, Types::Int16le
        # @!attribute max_setup_count
        #  The maximum number of setup bytes that the client will accept
        #  in transaction response.
        #  @return [Integer]
        define_field :max_setup_count, Types::Int8
        # @!attribute rsv1
        #  8-bit reserved field
        #  @return [Integer]
        define_field :rsv1, Types::Int8, default: 0
        # @!attribute flags
        #  16-bit flags
        #  @return [Integer]
        define_field :flags, Types::Int16le
        # @!attribute timeout
        #  32-bit timeout
        #  @return [Integer]
        define_field :timeout, Types::Int32le
        # @!attribute rsv2
        #  16-bit reserved field
        #  @return [Integer]
        define_field :rsv2, Types::Int16le, default: 0
        # @!attribute param_count
        #  16-bit number of transaction parameter bytes that the clients attempts to
        #  send to the server in this request.
        #  @return [Integer]
        define_field :param_count, Types::Int16le
        # @!attribute param_offset
        #  16-bit offset (in bytes) from the start of the SMB header to the start of the
        #  transaction parameters.
        #  @return [Integer]
        define_field :param_offset, Types::Int16le
        # @!attribute data_count
        #  16-bit number of transaction data bytes that the clients sends to
        #  the server in this request.
        #  @return [Integer]
        define_field :data_count, Types::Int16le
        # @!attribute data_offset
        #  16-bit offset (in bytes) from the start of the SMB header to the start
        #  of the data field.
        #  @return [Integer]
        define_field :data_offset, Types::Int16le
        # @!attribute setup_count
        #  8-bit number of setup words (ie 16-bit words) contained in {#setup} field.
        define_field :setup_count, Types::Int8
        # @!attribute rsv3
        #  8-bit reserved field
        #  @return [Integer]
        define_field :rsv3, Types::Int8
        # @!attribute setup
        #  Array of 2-byte words.
        define_field :setup, Types::ArrayOfInt16le, builder: ->(h, t) { t.new(counter: h[:setup_count]) }
        # @!attribute byte_count
        #  The size, in bytes, of the {#trans_name} field.
        #  @return [Integer]
        define_field :byte_count, Types::Int16le
        # @!padname
        #  8-bit optional padding to align {#name} on a 2-byte boundary.
        #  @return [Integer]
        define_field :padname, Types::Int8
        # @!attribute name
        #  Pathname of the mailslot or named pipe.
        #  @return [String]
        define_field :name, SMB::String
        # @!attribute pad1
        #  Padding to align {#body} on 4-byte boundary.
        #  @return [String]
        define_field :pad1, Types::String, default: "\0" * 4,
                     builder: ->(h, t) { s = t.new(length_from: -> { h.data_offset - SMB.new.sz - (h.offset_of(:name) + h[:name].sz) }) }
        define_field :body, Types::String
      end

      # Transaction Response.
      #
      # See also {Blocks}, as {Trans} is a specialization of {Blocks#words}
      # and {Blocks#bytes}.
      # @author Sylvain Daubert
      class TransResponse < Base
        # @!attribute word_count
        #  The size, in 2-byte words, of the SMB command parameters. It should
        #  be +14 + setup_count+.
        #  @return [Integer]
        define_field :word_count, Types::Int8, default: 10
        # @!attribute total_param_count
        #  The total number of transaction parameter bytes.
        #  @return [Integer]
        define_field :total_param_count, Types::Int16le
        # @!attribute total_data_count
        #  The total number of transaction data bytes.
        #  @return [Integer]
        define_field :total_data_count, Types::Int16le
        # @!attribute rsv1
        #  16-bit reserved field
        #  @return [Integer]
        define_field :rsv1, Types::Int16le, default: 0
        # @!attribute param_count
        #  16-bit number of transaction parameter bytes sent in this response.
        #  @return [Integer]
        define_field :param_count, Types::Int16le
        # @!attribute param_offset
        #  16-bit offset (in bytes) from the start of the SMB header to the start of the
        #  transaction parameters.
        #  @return [Integer]
        define_field :param_offset, Types::Int16le
        # @!attribute param_displacement
        #  16-bit offset (in bytes) relative to all of the transaction
        #  parameter bytes in this transaction response at which this block of
        #  parameter bytes SHOULD be placed.
        #  @return [Integer]
        define_field :param_displacement, Types::Int16le
        # @!attribute data_count
        #  16-bit number of transaction data bytes sent in this response.
        #  @return [Integer]
        define_field :data_count, Types::Int16le
        # @!attribute data_offset
        #  16-bit offset (in bytes) from the start of the SMB header to the start
        #  of the data field.
        #  @return [Integer]
        define_field :data_offset, Types::Int16le
        # @!attribute data_displacement
        #  16-bit offset (in bytes) relative to all of the transaction data bytes in
        #  this transaction response at which this block of data bytes SHOULD be placed.
        #  @return [Integer]
        define_field :data_displacement, Types::Int16le
        # @!attribute setup_count
        #  8-bit number of setup words (ie 16-bit words) contained in {#setup} field.
        define_field :setup_count, Types::Int8
        # @!attribute rsv3
        #  8-bit reserved field
        #  @return [Integer]
        define_field :rsv2, Types::Int8
        # @!attribute setup
        #  Array of 2-byte words.
        define_field :setup, Types::ArrayOfInt16le, builder: ->(h, t) { t.new(counter: h[:setup_count]) }
        # @!attribute byte_count
        #  The size, in bytes, of the {#trans_name} field.
        #  @return [Integer]
        define_field :byte_count, Types::Int16le
        define_field :pad1, Types::String, default: "\0" * 4,
                     builder: ->(h, t) { s = t.new(length_from: -> { h.data_offset - SMB.new.sz - (h.offset_of(:byte_count) + h[:byte_count].sz) }) }
        define_field :body, Types::String
      end
    end
    self.add_class SMB::TransRequest
    SMB.bind SMB::TransRequest, command: SMB::COMMANDS['trans'], flags: ->(v) { v.nil? ? 0 : (v & 0x80 == 0)}
    self.add_class SMB::TransResponse
    SMB.bind SMB::TransResponse, command: SMB::COMMANDS['trans'], flags: ->(v) { v.nil? ? 0 : (v & 0x80 == 0x80)}
  end
end
