module PacketGen
  module Header
    class TCP

      # Container for TCP options in {TCP TCP header}.
      # @author Sylvain Daubert
      class Options < Array

        # Read TCP header options from a string
        # @param [String] str binary string
        # @return [self]
        def read(str)
          self
        end

        # Get options binary string
        # @return [String]
        def to_s
          map(&:to_s).join
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
