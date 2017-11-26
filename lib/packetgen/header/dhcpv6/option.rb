# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class DHCPv6

      # DHCPv6 option
      #
      # A DHCPv6 consists of:
      # * a {#type} ({Types::Int16}),
      # * a {#length} ({Types::Int16}),
      # * and a {#data} ({Types::String}).
      #
      # Subclasses handles known options.
      # @author Sylvain Daubert
      class Option < Types::Fields
        
        # @!attribute type
        #  16-bit option type
        #  @return [Integer]
        define_field :type, Types::Int16
        # @!attribute length
        #  16-bit option length
        #  @return [Integer]
        define_field :length, Types::Int16
        # @!attribute data
        #  variable length option data
        #  @return [String]
        define_field :data, Types::String,
                     builder: ->(h,t) { t.new(length_from: h[:length]) }

        # Get Option subclasses
        # @return [Hash]
        def Option.subclasses
          return @klasses if defined? @klasses
          @klasses = []
          DHCPv6.constants.each do |cst|
            klass = DHCPv6.const_get(cst)
            next unless klass.is_a?(Class) and klass < Option
            @klasses[klass.new.type] = klass
          end
          @klasses
        end

        alias private_read read
        private :private_read

        # Populate object from binary string
        # @param [String] str
        # @return [Option]
        def read(str)
          if self.class == Option
            return self if str.nil?
            PacketGen.force_binary str
            type = Types::Int16.new.read(str).to_i
            klass = Option.subclasses[type]
            if klass
              klass.new.read(str)
            else
              private_read str
            end
          else
            private_read str
          end
        end

        def human_type
          if self.class == Option
            "option#{type}"
          else
            self.class.to_s.sub(/.*::/, '')
          end
        end

        def to_human
          str = "#{human_type}:"
          if respond_to? :human_data
            str << human_data
          elsif !self[:data].nil?
            str << data.inspect
          else
            # No data: only give option name
            human_type
          end
        end
      end
      
      class ClientID < Option
        delete_field :data
        define_field :duid, DUID
        
        def initialize(options={})
          super({type: 1}.merge(options))
        end

        def human_data
          self[:duid].to_human
        end
      end

      class ServerID < ClientID
        def initialize(options={})
          super({type: 2}.merge(options))
        end
      end

      # DHCPv6 Identity Association for Non-temporary Addresses Option
      class IANA < Option
        delete_field :data
        define_field :iaid, Types::Int32
        define_field :t1, Types::Int32
        define_field :t2, Types::Int32
        define_field :options, Types::String,
                     builder: ->(h,t) { t.new length_from: ->() { h[:length].to_i - 12 } }

        def initialize(options={})
          super({type: 3, length: 12}.merge(options))
        end

        def human_data
          "%#x,%u,%u" % [iaid, t1, t2]
        end
      end

      # DHCPv6 Identity Association for Temporary Addresses Option
      class IATA < Option
        delete_field :data
        define_field :iaid, Types::Int32
        define_field :options, Types::String,
                     builder: ->(h,t) { t.new length_from: ->() { h[:length].to_i - 4 } }

        def initialize(options={})
          super({type: 4, length: 4}.merge(options))
        end

        def human_data
          "%#x" % iaid
        end
      end

      # DHCPv6 IA Address option
      class IAAddr < Option
        delete_field :data
        define_field :ipv6, IPv6::Addr
        define_field :preferred_lifetime, Types::Int32
        define_field :valid_lifetime, Types::Int32
        define_field :options, Types::String,
                     builder: ->(h,t) { t.new length_from: ->() { h[:length].to_i - 24 } }

        def initialize(options={})
          super({type: 5, length: 24}.merge(options))
        end

        def human_data
          "#{ipv6},#{preferred_lifetime},#{valid_lifetime}"
        end
      end

      # List of requested options fo {ORO} option.
      # Set of {Types::Int16}
      class RequestedOptions < Types::Array
        set_of Types::Int16
      end

      # DHCPv6 Option Request Option
      class ORO < Option
        delete_field :data
        define_field :options, RequestedOptions
        def initialize(options={})
          super({type: 6}.merge(options))
        end
        
        def read(str)
          self[:type].read str[0, 2]
          self[:length].read str[2, 2]
          self[:options].read str[4, self.length]
          self
        end

        def human_data
          self[:options].to_human
        end
      end
      
      # DHCPv6 Preference option
      class Preference < Option
        delete_field :data
        define_field :value, Types::Int8
        
        def initialize(options={})
          super({type: 7}.merge(options))
        end
        
        def human_data
          value.to_s
        end
      end
      
      # DHCPv6 Elapsed Time option
      class ElapsedTime < Option
        delete_field :data
        define_field :value, Types::Int16
        
        def initialize(options={})
          super({type: 8}.merge(options))
        end
        
        def human_data
          value.to_s
        end
      end
      
      # DHCPv6 Relay Message option
      class RelayMessage < Option
        def initialize(options={})
          super({type: 9}.merge(options))
        end
      end

      # DHCPv6 Server Unicast option
      class ServerUnicast < Option
        delete_field :data
        define_field :addr, IPv6::Addr

        def initialize(options={})
          super({type: 12}.merge(options))
        end
        
        def human_data
          server_addr.to_human
        end
      end

      # DHCPv6 Status Code option
      class StatusCode < ElapsedTime
        def initialize(options={})
          super({type: 13}.merge(options))
        end
      end
      
      # DHCPv6 Rapid Commit option
      class RapidCommit < ElapsedTime
        delete_field :data

        def initialize(options={})
          super({type: 14}.merge(options))
        end
      end
    end
  end
end
