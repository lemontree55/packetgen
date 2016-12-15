# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module PcapNG

    # Mixin module to declare some common methods for block classes.
    module Block

      # Has this block option?
      # @return [Boolean]
      def has_options?
        self[:options].size > 0
      end

      # Calculate block length and update :block_len and block_len2 fields
      # @return [void]
      def recalc_block_len
        len = to_a.map(&:to_s).join.size
        self[:block_len].value = self[:block_len2].value = len
      end

      # Pad given field to 32 bit boundary, if needed
      # @param [Array<Symbol>] fields block fields to pad
      # @return [void]
      def pad_field(*fields)
        fields.each do |field|
          unless self[field].size % 4 == 0
            self[field] << "\x00" * (4 - (self[field].size % 4))
          end
        end
      end
    end
  end
end
