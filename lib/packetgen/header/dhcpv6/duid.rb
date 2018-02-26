# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

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
        }

        define_field :type, Types::Int16Enum, enum: TYPES
        define_field :body, Types::String
        
        def initialize(options={})
          super
        end

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
        
        def to_human
          "DUID<#{type},#{body.inspect}>"
        end
      end

      # DUID Based on Link-layer Address Plus Time
      # @author Sylvain Daubert
      class DUID_LLT < DUID
        delete_field :body
        undef body
        undef body=

        # Base time for time computation
        BASE_TIME = Time.utc(2000, 1, 1)
        
        define_field :htype, Types::Int16, default: 1
        define_field :time, Types::Int32, default: (Time.now - BASE_TIME).to_i
        define_field :link_addr, Eth::MacAddr

        def to_human
          real_time = BASE_TIME + self.time
          "DUID_LLT<#{real_time},#{link_addr}>"
        end
      end

      # DUID Based on Enterprise Number
      # @author Sylvain Daubert
      class DUID_EN < DUID
        delete_field :body
        undef body
        undef body=

        define_field :en, Types::Int32
        define_field :identifier, Types::String

        def to_human
          "DUID_EN<%#x,%s>" % [en, identifier]
        end
      end

      # DUID Based on Link-layer
      # @author Sylvain Daubert
      class DUID_LL < DUID
        delete_field :body
        undef body
        undef body=

        define_field :htype, Types::Int16, default: 1
        define_field :link_addr, Eth::MacAddr

        def to_human
          "DUID_LL<#{link_addr}>"
        end
      end
    end
  end
end
