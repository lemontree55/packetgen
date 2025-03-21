# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class TCP
      # Base class to describe a TCP option
      # @author Sylvain Daubert
      class Option < BinStruct::Struct
        include BinStruct::Structable

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
        define_attr :kind, BinStruct::Int8
        # @!attribute length
        #  Option length
        #  @return [Integer] 8-bit option length
        define_attr :length, BinStruct::Int8, optional: lambda(&:length?)
        # @!attribute value
        #  @return [Integer,String] option value
        define_attr :value, BinStruct::String, optional: ->(h) { h.length? && h.length > 2 },
                                               builder: ->(h, t) { t.new(length_from: -> { h.length - 2 }) }

        # @param [hash] options
        # @option options [Integer] :kind
        # @option options [Integer] :length
        # @option options [Integer,String] :value
        def initialize(options={})
          super
          case options[:value]
          when Integer
            klass = case self[:length].to_i
                    when 3 then BinStruct::Int8
                    when 4 then BinStruct::Int16
                    when 6 then BinStruct::Int32
                    else
                      raise ArgumentError, 'impossible length'
                    end
            self[:value] = klass.new(value: options[:value])
          when NilClass
            # Nothing to do
          else
            self[:value] = BinStruct::String.new.read(options[:value])
            self[:length].from_human(self[:value].sz + 2) unless options[:length]
          end
        end

        # Say if given option has a length field.
        # @return [Boolean]
        # @since 2.7.0
        def length?
          kind >= 2
        end

        undef value

        # Getter for value attribute
        # @return [String, Integer]
        def value
          case self[:value]
          when BinStruct::Int
            self[:value].to_i
          else
            self[:value].to_s
          end
        end

        # @private
        alias old_set_value value=

        # Setter for value attribute
        # @param[String,Integer] val
        # @return [String, Integer]
        def value=(val)
          case self[:value]
          when BinStruct::Int
            self.length = 2 + self[:value].sz
          when BinStruct::String
            self.length = 2 + BinStruct::String.new.read(val).sz
          end

          case val
          when Integer
            self[:value].from_human(val)
          else
            self[:value].read(val)
          end
          val
        end

        # Get binary string
        # @return [String]
        def to_s
          self.length = 2 + self[:value].sz if length?
          super
        end

        # Get option as a human readable string
        # @return [String]
        def to_human
          str = self.instance_of?(Option) ? "unk-#{kind}" : self.class.to_s.sub(/.*::/, '')
          str << ":#{self[:value].to_s.inspect}" if (length > 2) && !self[:value].to_s.empty?
          str
        end

        # @return [String]
        def inspect
          str = "#<#{self.class} kind=#{self[:kind].value.inspect} "
          str << "length=#{self[:length].value.inspect} " if self[:length].value
          str << "value=#{self[:value].inspect}>"
        end
      end

      # End Of Option TCP option
      # @author Sylvain Daubert
      class EOL < Option
        update_attr :kind, default: EOL_KIND
      end

      # No OPeration TCP option
      # @author Sylvain Daubert
      class NOP < Option
        # @see Option#initialize
        update_attr :kind, default: NOP_KIND
      end

      # Maximum Segment Size TCP option
      # @author Sylvain Daubert
      class MSS < Option
        update_attr :kind, default: MSS_KIND
        update_attr :length, default: 4

        # @see Option#initialize
        def initialize(options={})
          super
          self[:value] = BinStruct::Int16.new(value: options[:value])
        end

        # Get human-readable description
        # @return [String]
        def to_human
          "MSS:#{value}"
        end
      end

      # Window Size TCP option
      # @author Sylvain Daubert
      class WS < Option
        update_attr :kind, default: WS_KIND
        update_attr :length, default: 3

        # @see Option#initialize
        def initialize(options={})
          super
          self[:value] = BinStruct::Int8.new(value: options[:value])
        end

        # Get human-readable description
        # @return [String]
        def to_human
          "WS:#{value}"
        end
      end

      # Selective Acknowledgment OK TCP option
      # @author Sylvain Daubert
      class SACKOK < Option
        update_attr :kind, default: SACKOK_KIND
        update_attr :length, default: 2
      end

      # Selective Acknowledgment TCP option
      # @author Sylvain Daubert
      class SACK < Option
        update_attr :kind, default: SACK_KIND
      end

      # Echo TCP option
      # @author Sylvain Daubert
      class ECHO < Option
        update_attr :kind, default: ECHO_KIND
        update_attr :length, default: 6

        # @see Option#initialize
        def initialize(options={})
          super
          self[:value] = BinStruct::Int32.new(value: options[:value])
        end

        # Get human-readable description
        # @return [String]
        def to_human
          "WS:#{value}"
        end
      end

      # Echo Reply TCP option
      # @author Sylvain Daubert
      class ECHOREPLY < Option
        update_attr :kind, default: ECHOREPLY_KIND
        update_attr :length, default: 6

        # @see Option#initialize
        def initialize(options={})
          super
          self[:value] = BinStruct::Int32.new(value: options[:value])
        end

        # Get human-readable description
        # @return [String]
        def to_human
          "WS:#{value}"
        end
      end

      # Timestamp TCP option
      # @author Sylvain Daubert
      class TS < Option
        update_attr :kind, default: TS_KIND
        update_attr :length, default: 10

        # @see Option#initialize
        def initialize(options={})
          super
          self[:value].read(options[:value] || "\0" * 8)
        end

        # Get human-readable description
        # @return [String]
        def to_human
          value, echo_reply = self[:value].unpack('NN')
          "TS:#{value};#{echo_reply}"
        end
      end
    end
  end
end
