# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3

      # This class handles {OSPFv3 OSPFv3} Link State Acknownledgment packets
      # payload. The LSAck payload has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   +-                                                            +-+
      #   |                             LSAs                              |
      #   +-                                                            +-+
      #   |                              ...                              |
      # This paylod is implemented with only one field:
      # * {#lsas}, an {ArrayOfLSA} object.
      # @author Sylvain Daubert
      class LSAck < Base
        # @!attribute lsas
        #  Array of {LSA LSAs}
        #  @return [ArrayOfLSA]
        define_field :lsas, ArrayOfLSA,
                     builder: ->(h, t) { t.new(only_headers: true) }
      end
    end

    self.add_class OSPFv3::LSAck
    OSPFv3.bind_header OSPFv3::LSAck, type: OSPFv3::TYPES['LS_ACK']
  end
end
