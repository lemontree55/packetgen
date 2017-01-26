module PacketGen
  module Header
    class DNS

      # Define a DNS Ressource Record Section
      # @author Sylvain Daubert
      class RRSection < Types::Array

        # @api private
        # @param [DNS] dns
        # @param [Types::Int] counter
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
          force_binary str
          while str.length > 0 and self.size < @counter.to_i
            rr = RR.new(@dns).read(str)
            rr = OPT.new(@dns).read(str) if rr.has_type?('OPT')
            str.slice!(0, rr.sz)
            self.push rr
          end
          self
        end

        # Add a ressource record to this section. Increment associated counter
        # @param [RR,Hash] rr
        # @return [RRSection] self
        def <<(rr)
          push rr
          @counter.read(@counter.to_i + 1)
          self
        end

        # Delete a ressource
        # @param [RR] rr
        # @return [RR]
        def delete(rr)
          obj = super
          @counter.read(@counter.to_i - 1) if obj
          obj
        end

        private

        def record_from_hash(hsh)
          if hsh.has_key? :rtype
            case hsh.delete(:rtype)
            when 'Question'
              Question.new(@dns, hsh)
            when 'OPT'
              OPT.new(@dns, hsh)
            when 'RR'
              RR.new(@dns, hsh)
            else
              raise TypeError, 'rtype should be a Question, OPT or RR'
            end
          else
            hsh
          end
        end
      end
    end
  end
end
