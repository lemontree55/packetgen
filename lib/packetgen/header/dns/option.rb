module PacketGen
  module Header
    class DNS

      # @author Sylvain Daubert
      class Option < Struct.new(:code, :length, :data)
        include StructFu

        # @param [Hash] options
        # @option options [Integer] :code
        # @option options [Integer] :length
        # @option options [String] :data
        def initialize(options={})
          super Int16.new(options[:code]),
                Int16.new(options[:length]),
                StructFu::String.new.read(options[:data])
        end

        # Read A EDNS option from a string
        # @param [String] str
        # @return [Option] self
        def read(str)
          return self if str.nil?
          force_binary str
          self[:code].read str[0, 2]
          self[:length].read str[2, 2]
          self[:data].read str[4, self.length]
          self
        end

        # Getter for code attribute
        # @return [Integer]
        def code
          self[:code].to_i
        end

        # Setter for code attribute
        # @param [Integer] v
        # @return [Integer]
        def code=(v)
          self[:code].read = v
        end

        # Getter for length attribute
        # @return [Integer]
        def length
          self[:length].to_i
        end

        # Setter for length attribute
        # @param [Integer] v
        # @return [Integer]
        def length=(v)
          self[:length].read = v
        end

        # @return [String]
        def to_human
          "code=#{code},len=#{length},data=#{data.inspect}"
        end
      end
    end
  end
end
