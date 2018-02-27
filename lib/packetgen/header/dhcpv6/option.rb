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

        class << self
          # Get Option subclasses
          # @return [Hash]
          def subclasses
            return @klasses if defined? @klasses
            @klasses = []
            DHCPv6.constants.each do |cst|
              klass = DHCPv6.const_get(cst)
              next unless klass.is_a?(Class) and klass < Option
              @klasses[klass.new.type] = klass
            end
            @klasses
          end

          # Create a new Option object (or a subclass)
          # @param [Hash] options
          # @return [Option]
          def new(options={})
            if self == Option
              case options[:type]
              when Integer
                klass = Option.subclasses[options[:type]]
                klass.new(options) if klass
              when String
                if DHCPv6.const_defined?(options[:type])
                  klass = DHCPv6.const_get(options[:type])
                  options.delete :type
                  klass.new(options) if klass < Option
                end
              else
                super
              end
            else
              super
            end
          end
        end

        def initialize(options={})
          if self.class.const_defined?(:TYPE) and options[:type].nil?
            options[:type] = self.class.const_get(:TYPE)
          end
          if options[:data]
            options[:length] = options[:data].to_s.size
          end
          super
          if options[:data].nil?
            self.length = self.sz - 4
          end
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
          if respond_to? :human_data and human_data.size > 0
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
        # Option type value
        TYPE = 1

        delete_field :data
        undef data
        define_field :duid, DUID
        
        # Get human-readable data (DUID)
        # @return [String]
        def human_data
          self[:duid].to_human
        end
      end

      class ServerID < ClientID
        # Option type value
        TYPE = 2
      end

      # DHCPv6 Identity Association for Non-temporary Addresses Option
      class IANA < Option
        # Option type value
        TYPE = 3

        delete_field :data
        undef data
        define_field :iaid, Types::Int32
        define_field :t1, Types::Int32
        define_field :t2, Types::Int32
        define_field :options, Types::String,
                     builder: ->(h,t) { t.new length_from: ->() { h[:length].to_i - 12 } }

        def human_data
          "%#x,%u,%u" % [iaid, t1, t2]
        end
      end

      # DHCPv6 Identity Association for Temporary Addresses Option
      class IATA < Option
        # Option type value
        TYPE = 4

        delete_field :data
        undef data
        define_field :iaid, Types::Int32
        define_field :options, Types::String,
                     builder: ->(h,t) { t.new length_from: ->() { h[:length].to_i - 4 } }

        def human_data
          "%#x" % iaid
        end
      end

      # DHCPv6 IA Address option
      class IAAddr < Option
        # Option type value
        TYPE = 5

        delete_field :data
        undef data
        define_field :ipv6, IPv6::Addr
        define_field :preferred_lifetime, Types::Int32
        define_field :valid_lifetime, Types::Int32
        define_field :options, Types::String,
                     builder: ->(h,t) { t.new length_from: ->() { h[:length].to_i - 24 } }

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
        # Option type value
        TYPE = 6

        delete_field :data
        undef data
        define_field :options, RequestedOptions
        
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
        # Option type value
        TYPE = 7

        delete_field :data
        undef data
        define_field :value, Types::Int8
        
        def human_data
          value.to_s
        end
      end
      
      # DHCPv6 Elapsed Time option
      class ElapsedTime < Option
        # Option type value
        TYPE = 8

        delete_field :data
        undef data
        define_field :value, Types::Int16

        def human_data
          value.to_s
        end
      end
      
      # DHCPv6 Relay Message option
      class RelayMessage < Option
        # Option type value
        TYPE = 9
      end

      # DHCPv6 Server Unicast option
      class ServerUnicast < Option
        # Option type value
        TYPE = 12

        delete_field :data
        undef data
        define_field :addr, IPv6::Addr

        def human_data
          addr
        end
      end

      # DHCPv6 Status Code option
      class StatusCode < ElapsedTime
        # Option type value
        TYPE = 13
      end
      
      # DHCPv6 Rapid Commit option
      class RapidCommit < Option
        # Option type value
        TYPE = 14

        delete_field :data
        undef data
      end
    end
  end
end
