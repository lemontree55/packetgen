module PacketGen
  module Header
    class DNS

      # Define a DNS Ressource Record Section
      # @author Sylvain Daubert
      class RRSection < Array

        # @api private
        # @param [DNS] dns
        # @param [StructFu::Int] counter
        def initialize(dns, counter)
          @dns = dns
          @counter = counter
        end

        # Read RR section from a string
        # @param [String] str binary string
        # @return [RRSection] self
        def read(str)
          clear
          return self if str.nil?
          PacketGen.force_binary str
          while str.length > 0 and self.size < @counter.to_i
            rr = RR.new(@dns).read(str)
            rr = OPT.new(@dns).read(str) if rr.has_type?('OPT')
            str.slice!(0, rr.sz)
            self.push rr
          end
          self
        end

        # Add a ressource record to this section
        # @param [RR] rr
        # @return [RRSectrion] self
        def <<(rr)
          super
          @counter.read(@counter.to_i + 1)
        end

        # Delete a ressource
        # @param [RR] rr
        # @return [RR]
        def delete(rr)
          obj = super
          @counter.read(@counter.to_i - 1) if obj
          obj
        end

        # Get options binary string
        # @return [String]
        def to_s
          map(&:to_s).join
        end

        # Get a human readable string
        # @return [String]
        def to_human
          map(&:to_human).join(',')
        end

        # Get options size in bytes
        # @return [Integer]
        def sz
          to_s.size
        end
      end
    end
  end
end
