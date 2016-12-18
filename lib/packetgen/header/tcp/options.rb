module PacketGen
  module Header
    class TCP

      # Container for TCP options in {TCP TCP header}.
      # @author Sylvain Daubert
      class Options < Array

        # Get {Option} subclasses
        # @return [Array<Class>]
        def self.option_classes
          return @klasses if defined? @klasses
          @klasses = []
          Option.constants.each do |cst|
            next unless cst.to_s.end_with? '_KIND'
            optname = cst.to_s.sub(/_KIND/, '')
            @klasses[Option.const_get(cst)] = TCP.const_get(optname)
          end
          @klasses
        end

        # Read TCP header options from a string
        # @param [String] str binary string
        # @return [self]
        def read(str)
          clear
          return self if str.nil?
          PacketGen.force_binary str

          i = 0
          klasses = self.class.option_classes
          while i < str.to_s.length
            kind = str[i, 1].unpack('C').first
            this_option = if klasses[kind].nil?
                            Option.new
                          else
                            klasses[kind].new
                          end
            this_option.read str[i, str.size]
            unless this_option.has_length?
              this_option.length = nil
              this_option.value = nil
            end
            self << this_option
            i += this_option.sz
          end
          self
        end

        # Add a well-known option
        # @param [String] opt option name
        # @param [Object] value
        # @return [self]
        # @raise [ArgumentError] unknown option
        def add(opt, value=nil)
          raise ArgumentError, "unknown option #{opt}" unless TCP.const_defined?(opt)
          klass = TCP.const_get(opt)
          raise ArgumentError "unknown option #{opt}" unless klass < Option
          option = klass.new(value: value)
          self << option
          self
        end

        # Get options binary string
        # @return [String]
        def to_s
          map(&:to_s).join
        end

        # Get a human readable string
        # @return [String]
        def to_human
          map(&:to_human).join(', ')
        end

        # Get options size in bytes
        # @return [Integer]
        def sz
          to_s.length
        end
      end
    end
  end
end

require_relative 'option'
