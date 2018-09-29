# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class DHCPv6
      # @abstract Base class for DUID (DHCP Unique ID)
      # @author Sylvain Daubert
      class DUID < Types::Fields
        TYPES = {
          'DUID-LLT' => 1,
          'DUID-EN'  => 2,
          'DUID-LL'  => 3
        }.freeze

        # @!attribute type
        #  16-bit DUID type
        #  @return [Integer]
        define_field :type, Types::Int16Enum, enum: TYPES
        # @!attribute body
        #  @abstract replaced by specific fields in subclasses
        #  DUID data.
        #  @return [String]
        define_field :body, Types::String

        alias private_read read
        private :private_read

        # Populate object from binary string
        # @param [String] str
        # @return [DUID]
        def read(str)
          if self.class == DUID
            super
            case type
            when 1
              DUID_LLT.new.read(str)
            when 2
              DUID_EN.new.read(str)
            when 3
              DUID_LL.new.read(str)
            else
              self
            end
          else
            private_read str
          end
        end

        # Get human-readable DUID description
        # @return [String]
        def to_human
          "DUID<#{type},#{body.inspect}>"
        end
      end

      # DUID Based on Link-layer Address Plus Time
      # @author Sylvain Daubert
      class DUID_LLT < DUID
        remove_field :body

        # Base time for time computation
        BASE_TIME = Time.utc(2000, 1, 1)

        # @!attribute htype
        #  16-bit hardware protocol type
        #  @return [Integer]
        define_field :htype, Types::Int16, default: 1
        # @!attribute time
        #  32-bit time information
        #  @return [Time]
        define_field :time, Types::Int32, default: (Time.now - BASE_TIME).to_i
        # @!attribute link_addr
        #  @return [Eth::MacAddr]
        define_field :link_addr, Eth::MacAddr

        # @return [Time]
        def time
          BASE_TIME + self[:time].to_i
        end

        # @param [Time] time
        # @return [Time]
        def time=(time)
          self[:time].value = time - BASE_TIME
        end

        # Get human-readable DUID description
        # @return [String]
        def to_human
          "DUID_LLT<#{time},#{link_addr}>"
        end
      end

      # DUID Based on Enterprise Number
      # @author Sylvain Daubert
      class DUID_EN < DUID
        remove_field :body

        # @!attribute en
        #  32-bit entreprise number
        #  @return [Integer]
        define_field :en, Types::Int32
        # @!attribute identifier
        #  @return [String]
        define_field :identifier, Types::String

        # Get human-readable DUID description
        # @return [String]
        def to_human
          'DUID_EN<%#x,%s>' % [en, identifier]
        end
      end

      # DUID Based on Link-layer
      # @author Sylvain Daubert
      class DUID_LL < DUID
        remove_field :body

        # @!attribute htype
        #  16-bit hardware protocol type
        #  @return [Integer]
        define_field :htype, Types::Int16, default: 1
        # @!attribute link_addr
        #  @return [Eth::MacAddr]
        define_field :link_addr, Eth::MacAddr

        # Get human-readable DUID description
        # @return [String]
        def to_human
          "DUID_LL<#{link_addr}>"
        end
      end
    end
  end
end
