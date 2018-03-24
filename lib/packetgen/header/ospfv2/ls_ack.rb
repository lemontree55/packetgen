# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv2

      # This class handles {OSPFv2 OSPFv2} LS Acknowledgment packets payload.
      # The LS Acknowledgment payload has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   +-                                                             -+
      #   |                                                               |
      #   +-                      An LSA Header                          -+
      #   |                                                               |
      #   +-                                                             -+
      #   |                                                               |
      #   +-                                                             -+
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                              ...                              |
      # This paylod is implemented as a unique field: {#lsas}, which is an
      # {ArrayOfLSAHeader} object.
      # @author Sylvain Daubert
      class LSAck < Base
        # @!attribute lsas
        #  Array of LSA headers
        #  @return [ArrayOfLSAHeader]
        define_field :lsas, ArrayOfLSAHeader
      end
    end

    self.add_class OSPFv2::LSAck
    OSPFv2.bind_header OSPFv2::LSAck, type: OSPFv2::TYPES['LS_ACK']
  end
end
