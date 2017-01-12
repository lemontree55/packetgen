require_relative 'label'

module PacketGen
  module Header
    class DNS

      class Labels < Array

        POINTER_MASK = 0xc000

        attr_reader :dns

        # @param [DNS] dns
        def initialize(dns)
          super()
          @dns = dns
          @pointer = nil
          @pointer_name = nil
        end

        # Read a set of labels form a dotted string
        # @param [String] str
        # @return [Labels] self
        def parse(str)
          clear
          self
        end

        # Read a sequence of label from a string
        # @param [String] str binary string
        # @return [Labels] self
        def read(str)
          @pointer = nil
          @pointer_name = nil
          return self if str.nil?
          PacketGen.force_binary str
          start = 0
          while true
            index = str[start, 2].unpack('n').first
            if pointer? index
              # Pointer on another label
              @pointer = str[start, 2]
              break
            else
              label = Label.new.read(str[start..-1])
              start += label.sz
              self << label
              break if label.length == 0 or str.length == 0
            end
          end
          self
        end

        # Get options binary string
        # @return [String]
        def to_s
          map(&:to_s).join + @pointer.to_s
        end

        # Get a human readable string
        # @return [String]
        def to_human
          map(&:to_human).join('.') + name_from_pointer
        end

        # Get options size in bytes
        # @return [Integer]
        def sz
          to_s.size
        end

        private

        def pointer?(index)
          index & POINTER_MASK == POINTER_MASK
        end

        def name_from_pointer
          return '' unless @pointer
          return @pointer_name if @pointer_name
          
          index = @pointer.unpack('n').first
          mask = ~POINTER_MASK & 0xffff
          ptr = index & mask
          @pointer_name = Labels.new(@dns).read(self.dns.to_s[ptr..-1]).to_human
        end
      end
    end
  end
end
