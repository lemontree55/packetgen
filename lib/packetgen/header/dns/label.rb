module PacketGen
  module Header
    class DNS

      class Label < Struct.new(:length, :label)
        include StructFu

        # @overload initialize(str)
        #  @param [String] label
        #  @return [Label]
        # @overload initialize(options={})
        #  @param [Hash] options
        #  @option options [Integer] :length
        #  @option options [String] :label
        #  @return [Label]
        # @return [Label]
        def initialize(options={})
          super Int8.new, StructFu::String.new

          case options
          when Hash
            self[:length].read options[:length]
            self[:label].read options[:label]
          else
            str = options.to_s
            self[:length].read str.length
            self[:label].read str
          end

          # Read DNS label from a string
          # @param [String] str binary string
          # @return [Label] self
          def read(str)
            return self if str.nil?
            force_binary str
            self[:length].read str[0, 1]
            self[:label].read str[1, self.length]
            self
          end

          def length
            self[:length].to_i
          end

          def length=(l)
            self[:length].read l
          end

          def to_human
            self[:label].to_s
          end
        end
      end
    end
  end
end

