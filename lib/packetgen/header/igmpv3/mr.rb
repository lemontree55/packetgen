# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require_relative 'group_record'

module PacketGen
  module Header
    class IGMPv3
      # IGMPv3 Membership Report.
      #
      # This is a subpayload for IGMPv3 packets only. This kind of payload is
      # sent by IP systems to report (to neighboring routers) the current multicast
      # reception state, or changes in the multicast reception state, of their
      # interfaces. Reports have the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |           Reserved            |  Number of Group Records (M)  |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   .                                                               .
      #   .                        Group Record [1]                       .
      #   .                                                               .
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   .                                                               .
      #   .                        Group Record [2]                       .
      #   .                                                               .
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                               .                               |
      #   .                               .                               .
      #   |                               .                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   .                                                               .
      #   .                        Group Record [M]                       .
      #   .                                                               .
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class MR < Base
        # @!attribute reserved
        #  16-bit reserved field
        # @return [Integer]
        define_attr :reserved, BinStruct::Int16, default: 0
        # @!attribute number_of_gr
        #  16-bit Number of group records in {#group_records}
        #  @return [Integer]
        define_attr :number_of_gr, BinStruct::Int16, default: 0

        # @!attribute group_records
        #  Array of group records
        #  @return [GroupRecords]
        define_attr :group_records, GroupRecords,
                    builder: ->(h, t) { t.new(counter: h[:number_of_gr]) }
      end
    end

    self.add_class IGMPv3::MR
    IGMPv3.bind IGMPv3::MR, type: 0x22
  end
end
