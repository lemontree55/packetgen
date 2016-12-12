module PacketGen
  module Header
    class TCP

      # Base class to describe a TCP option
      # @author Sylvain Daubert
      class Option < Struct.new(:kind, :length, :value)
        include StructFu

        EOL_KIND       = 0
        NOP_KIND       = 1
        MSS_KIND       = 2
        WS_KIND        = 3
        SACKOK_KIND    = 4
        SACK_KIND      = 5
        ECHO_KIND      = 6
        ECHOREPLY_KIND = 7
        TS_KIND        = 8

        # @param [hash] options
        # @option options [Integer] :kind
        # @option options [Integer] :length
        # @option options [Integer,String] :value
        def initialize(options={})
          super Int8.new(options[:kind]),
                Int8.new(options[:length])

          case options[:value]
          when Integer
            klass = case self[:length].to_i
                    when 3; Int8
                    when 4; Int16
                    when 6; Int32
                    else
                      raise ArgumentError, 'impossible length'
                    end
            self[:value] = klass.new(options[:value])
          when NilClass
            self[:value] = StructFu::String.new
          else
            self[:value] = StructFu::String.new.read(options[:value])
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
            if str[2, 1] && length > 2
              self[:value].read str[2, length - 2]
            end
          end
          self
        end

        # Getter for kind attribute
        # @return [Integer]
        def kind
          self[:kind].to_i
        end

        # Setter for kind attribute
        # @param [Integer] i
        # @return [Integer]
        def kind=(i)
          self[:kind].read i
        end

        # Getter for length attribute
        # @return [Integer]
        def length
          self[:length].to_i
        end

        # Setter for length attribute
        # @param [Integer] i
        # @return [Integer]
        def length=(i)
          self[:length].read i
        end

        # Say if option has a length
        # @return [Boolean]
        def has_length?
          self[:kind].value && kind >= 2
        end

        # Getter for value attribute
        # @return [String, Integer]
        def value
          case self[:value]
          when StructFu::Int
            self[:value].to_i
          else
            self[:value].to_s
          end
        end

        # Setter for value attribute
        # @param [String, Integer] v
        # @return [String, Integer]
        def value=(v)
          self[:value].read v
        end

        # Get binary string
        # @return [String]
        def to_s
          str = self[:kind].to_s
          str << self[:length].to_s unless self[:length].value.nil?
          str << self[:value].to_s if length > 2
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
          self[:value] = Int16.new(options[:value])
        end
      end

      # Window Size TCP option
      # @author Sylvain Daubert
      class WS < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: WS_KIND, length: 3)
          self[:value] = Int8.new(options[:value])
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
          self[:value] = Int32.new(options[:value])
        end
      end

      # Echo Reply TCP option
      # @author Sylvain Daubert
      class ECHOREPLY < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: ECHOREPLY_KIND, length: 6)
          self[:value] = Int32.new(options[:value])
        end
      end

      # Timestamp TCP option
      # @author Sylvain Daubert
      class TS < Option
        # @see Option#initialize
        def initialize(options={})
          super options.merge!(kind: TS_KIND, length: 10)
          self[:value] = StructFu::String.new.read(options[:value] || "\0" * 8)
        end
      end
    end
  end
end

