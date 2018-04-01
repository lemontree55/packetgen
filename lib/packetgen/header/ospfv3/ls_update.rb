# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3

      # This class handles {OSPFv3 OSPFv3} Link State Update packets
      # payload. The LSU payload has the following format:
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                            # LSAs                             |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                                                               |
      #   +-                                                            +-+
      #   |                             LSAs                              |
      #   +-                                                            +-+
      #   |                              ...                              |
      # This paylod is implemented with two fields:
      # * {#lsas_count}, a {Types::Int32} field,
      # * and {#lsas}, an {ArrayOfLSA} object.
      # @author Sylvain Daubert
      class LSUpdate < Base
        # @!attribute lsas_count
        #  Count of LSAs included in this update
        #  @return [Integer]
        define_field :lsas_count, Types::Int32
        # @!attribute lsas
        #  Array of {LSA LSAs}
        #  @return [ArrayOfLSA]
        define_field :lsas, ArrayOfLSA,
                     builder: ->(h, t) { t.new(counter: h[:lsas_count]) }
        
        # Calculate checksums of all LSAs
        # @return [void]
        def calc_checksum
          lsas.each { |lsa| lsa.calc_checksum }
        end
        
        # Calculate length of all LSAs
        def calc_length
          lsas.each { |lsa| lsa.calc_length }
        end
      end
    end

    self.add_class OSPFv3::LSUpdate
    OSPFv3.bind_header OSPFv3::LSUpdate, type: OSPFv3::TYPES['LS_UPDATE']
  end
end
