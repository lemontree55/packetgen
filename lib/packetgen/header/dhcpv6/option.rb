# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class DHCPv6
      # A DHCPv6 consists of:
      # * a {#type} ({Types::Int16}),
      # * a {#length} ({Types::Int16}),
      # * and a {#data} ({Types::String}).
      #
      # Subclasses handles known options. These subclasses may remove {#data}
      # field to replace it by specific option field(s).
      # @author Sylvain Daubert
      class Option < Types::Fields
        include Types::Fieldable

        # @!attribute type
        #  16-bit option type
        #  @return [Integer]
        define_field :type, Types::Int16
        # @!attribute length
        #  16-bit option length
        #  @return [Integer]
        define_field :length, Types::Int16
        # @!attribute data
        #  variable length option data.
        #  @return [String]
        define_field :data, Types::String,
                     builder: ->(h, t) { t.new(length_from: h[:length]) }

        class << self
          # Get Option subclasses
          # @return [Hash]
          def subclasses
            return @klasses if defined? @klasses

            @klasses = []
            DHCPv6.constants.each do |cst|
              klass = DHCPv6.const_get(cst)
              next unless klass.is_a?(Class) && (klass < Option)

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
                klass&.new(options)
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

        # Create an Option
        # @param [Hash] options
        def initialize(options={})
          options[:length] = options[:data].to_s.size if options[:data]
          super
          self.length = self.sz - 4 if options[:data].nil?
        end

        alias private_read read
        private :private_read

        # Get human-readable {#type}
        # @return [String]
        def human_type
          if self.instance_of?(Option)
            "option#{type}"
          else
            self.class.to_s.sub(/.*::/, '')
          end
        end

        # Get a human-readable string for this option
        # @return [String]
        def to_human
          str = +"#{human_type}:"
          if respond_to?(:human_data) && !human_data.empty?
            str << human_data
          elsif !self[:data].nil?
            str << data.inspect
          else
            # No data: only give option name
            human_type
          end
        end
      end

      # DHCPv6 Client ID option
      # @author Sylvain Daubert
      class ClientID < Option
        update_field :type, default: 1
        remove_field :data

        # @!attribute duid
        #  @return [DUID]
        define_field :duid, DUID

        # Get human-readable data (DUID)
        # @return [String]
        def human_data
          self[:duid].to_human
        end
      end

      # DHCPv6 Server ID option
      # @author Sylvain Daubert
      class ServerID < ClientID
        update_field :type, default: 2
      end

      # DHCPv6 Identity Association for Non-temporary Addresses Option
      # @author Sylvain Daubert
      class IANA < Option
        update_field :type, default: 3
        remove_field :data

        # @!attribute iaid
        #  32-bit IAID field
        #  @return [Integer]
        define_field :iaid, Types::Int32
        # @!attribute t1
        #  32-bit T1 field
        #  @return [Integer]
        define_field :t1, Types::Int32
        # @!attribute t2
        #  32-bit T2 field
        #  @return [Integer]
        define_field :t2, Types::Int32
        # @!attribute options
        #  options field
        #  @return [String]
        define_field :options, Types::String,
                     builder: ->(h, t) { t.new length_from: -> { h[:length].to_i - 12 } }

        # Get human-readable data (IAID, T1 and T2)
        # @return [String]
        def human_data
          '%#x,%u,%u' % [iaid, t1, t2]
        end
      end

      # DHCPv6 Identity Association for Temporary Addresses Option
      # @author Sylvain Daubert
      class IATA < Option
        update_field :type, default: 4
        remove_field :data

        # @!attribute iaid
        #  32-bit IAID field
        #  @return [Integer]
        define_field :iaid, Types::Int32
        # @!attribute options
        #  options field
        #  @return [String]
        define_field :options, Types::String,
                     builder: ->(h, t) { t.new length_from: -> { h[:length].to_i - 4 } }

        # Get human-readable data (IAID)
        # @return [String]
        def human_data
          '%#x' % iaid
        end
      end

      # DHCPv6 IA Address option
      # @author Sylvain Daubert
      class IAAddr < Option
        update_field :type, default: 5
        remove_field :data

        # @attribute ipv6
        #  IPv6 address
        # @return [IPv6::Addr]
        define_field :ipv6, IPv6::Addr
        # @attribute preferred_lifetime
        #  32-bit preferred lifetime
        #  @return [Integer]
        define_field :preferred_lifetime, Types::Int32
        # @attribute valid_lifetime
        #  32-bit valid lifetime
        #  @return [Integer]
        define_field :valid_lifetime, Types::Int32
        # @!attribute options
        #  options field
        #  @return [String]
        define_field :options, Types::String,
                     builder: ->(h, t) { t.new length_from: -> { h[:length].to_i - 24 } }

        # Get human-readable data (ipv6, preferred lifetime and valid lifetime)
        # @return [String]
        def human_data
          "#{ipv6},#{preferred_lifetime},#{valid_lifetime}"
        end
      end

      # List of requested options for {ORO} option.
      # Set of {Types::Int16}
      # @author Sylvain Daubert
      class RequestedOptions < Types::Array
        set_of Types::Int16
      end

      # DHCPv6 Option Request Option
      # @author Sylvain Daubert
      class ORO < Option
        update_field :type, default: 6
        remove_field :data

        # @!attribute options
        #   @return [RequestedOptions]
        define_field :options, RequestedOptions, builder: ->(h, t) { t.new(length_from: h[:length]) }

        # Get human-readable data
        # @return [String]
        def human_data
          self[:options].to_human
        end
      end

      # DHCPv6 Preference option
      # @author Sylvain Daubert
      class Preference < Option
        update_field :type, default: 7
        remove_field :data

        # @!attribute value
        #  8-bit value
        #  @return [Integer]
        define_field :value, Types::Int8

        # Get human-readable data (value)
        # @return [String]
        def human_data
          value.to_s
        end
      end

      # DHCPv6 Elapsed Time option
      # @author Sylvain Daubert
      class ElapsedTime < Option
        update_field :type, default: 8
        remove_field :data

        # @!attribute value
        #  16-bit value
        #  @return [Integer]
        define_field :value, Types::Int16

        # Get human-readable data (value)
        # @return [String]
        def human_data
          value.to_s
        end
      end

      # DHCPv6 Relay Message option
      # @author Sylvain Daubert
      class RelayMessage < Option
        update_field :type, default: 9
      end

      # DHCPv6 Server Unicast option
      # @author Sylvain Daubert
      class ServerUnicast < Option
        update_field :type, default: 12
        remove_field :data

        # @!attribute addr
        #  IPv6 server address
        # @return [IPv6::Addr]
        define_field :addr, IPv6::Addr

        # Get human-readable data (addr)
        # @return [String]
        def human_data
          addr
        end
      end

      # DHCPv6 Status Code option
      # @author Sylvain Daubert
      class StatusCode < ElapsedTime
        update_field :type, default: 13
      end

      # DHCPv6 Rapid Commit option
      # @author Sylvain Daubert
      class RapidCommit < Option
        update_field :type, default: 14
        remove_field :data
      end
    end
  end
end
