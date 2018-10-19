# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class TCP
      # Base class to describe a TCP option
      # @author Sylvain Daubert
      class Option < Base
        # EOL option value
        EOL_KIND       = 0
        # NOP option value
        NOP_KIND       = 1
        # MSS option value
        MSS_KIND       = 2
        # WS option value
        WS_KIND        = 3
        # SACKOK option value
        SACKOK_KIND    = 4
        # SACK option value
        SACK_KIND      = 5
        # ECHO option value
        ECHO_KIND      = 6
        # ECHOREPLY option value
        ECHOREPLY_KIND = 7
        # TS option value
        TS_KIND        = 8

        # @!attribute kind
        #  Option kind
        #  @return [Integer] 8-bit option kind
        define_field :kind, Types::Int8
        # @!attribute length
        #  Option length
        #  @return [Integer] 8-bit option length
        define_field :length, Types::Int8
        # @!attribute value
        #  @return [Integer,String] option value
        define_field :value, Types::String

        # @param [hash] options
        # @option options [Integer] :kind
        # @option options [Integer] :length
        # @option options [Integer,String] :value
        def initialize(options={})
          super
          case options[:value]
          when Integer
            klass = case self[:length].to_i
                    when 3 then Types::Int8
                    when 4 then Types::Int16
                    when 6 then Types::Int32
                    else
                      raise ArgumentError, 'impossible length'
                    end
            self[:value] = klass.new(options[:value])
          when NilClass
            self[:value] = Types::String.new
          else
            self[:value] = Types::String.new.read(options[:value])
            self[:length].read(self[:value].sz + 2) unless options[:length]
          end
        end

        # Read a TCP option from a string
        # @param [String] str binary string
        # @return [self]
        def read(str)
          return self if str.nil?
          force_binary str
          self[:kind].read str[0, 1]
          if str[1, 1]
            self[:length].read str[1, 1]
            self[:value].read str[2, length - 2] if str[2, 1] && length > 2
          end
          self
        end

        # Say if given option has a length field.
        # @return [Boolean]
        # @since 2.7.0
        def length?
          self[:kind].value && kind >= 2
        end

        # Getter for value attribute
        # @return [String, Integer]
        def value
          case self[:value]
          when Types::Int
            self[:value].to_i
          else
            self[:value].to_s
          end
        end

        # Get binary string
        # @return [String]
        def to_s
          str = self[:kind].to_s
          str << self[:length].to_s unless self[:length].value.nil?
          str << self[:value].to_s if length > 2
          str
        end

        # Get option as a human readable string
        # @return [String]
        def to_human
          str = self.class == Option ? "unk-#{kind}" : self.class.to_s.sub(/.*::/, '')
          if (length > 2) && !self[:value].to_s.empty?
            str << ":#{self[:value].to_s.inspect}"
          end
          str
        end

        # @return [String]
        def inspect
          str = +"#<#{self.class} kind=#{self[:kind].value.inspect} "
          str << "length=#{self[:length].value.inspect} " if self[:length].value
          str << "value=#{self[:value].inspect}>"
        end
      end

      # End Of Option TCP option
      # @author Sylvain Daubert
      class EOL < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: EOL_KIND)
        end
      end

      # No OPeration TCP option
      # @author Sylvain Daubert
      class NOP < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: NOP_KIND)
        end
      end

      # Maximum Segment Size TCP option
      # @author Sylvain Daubert
      class MSS < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: MSS_KIND, length: 4)
          self[:value] = Types::Int16.new(options[:value])
        end

        # @return [String]
        def to_human
          "MSS:#{value}"
        end
      end

      # Window Size TCP option
      # @author Sylvain Daubert
      class WS < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: WS_KIND, length: 3)
          self[:value] = Types::Int8.new(options[:value])
        end

        # @return [String]
        def to_human
          "WS:#{value}"
        end
      end

      # Selective Acknowledgment OK TCP option
      # @author Sylvain Daubert
      class SACKOK < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: SACKOK_KIND, length: 2)
        end
      end

      # Selective Acknowledgment TCP option
      # @author Sylvain Daubert
      class SACK < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: SACK_KIND)
          self[:length].read(2) if self[:value].to_s == ''
        end
      end

      # Echo TCP option
      # @author Sylvain Daubert
      class ECHO < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: ECHO_KIND, length: 6)
          self[:value] = Types::Int32.new(options[:value])
        end

        # @return [String]
        def to_human
          "WS:#{value}"
        end
      end

      # Echo Reply TCP option
      # @author Sylvain Daubert
      class ECHOREPLY < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: ECHOREPLY_KIND, length: 6)
          self[:value] = Types::Int32.new(options[:value])
        end

        # @return [String]
        def to_human
          "WS:#{value}"
        end
      end

      # Timestamp TCP option
      # @author Sylvain Daubert
      class TS < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: TS_KIND, length: 10)
          self[:value] = Types::String.new.read(options[:value] || "\0" * 8)
        end

        # @return [String]
        def to_human
          value, echo_reply = self[:value].unpack('NN')
          "TS:#{value};#{echo_reply}"
        end
      end
    end
  end
end
