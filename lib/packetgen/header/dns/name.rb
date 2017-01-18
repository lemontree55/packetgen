module PacketGen
  module Header
    class DNS

      # DNS Name, defined as a suite of labels. A label is of type {StructFu::IntString}.
      # @author Sylvain Daubert
      class Name < Array

        # Mask to decode a pointer on another label
        POINTER_MASK = 0xc000

        # @return [DNS]
        attr_accessor :dns

        # @param [DNS] dns
        def initialize
          super
          @pointer = nil
          @pointer_name = nil
        end

        # Read a set of labels form a dotted string
        # @param [String] str
        # @return [Name] self
        def from_human(str)
          clear
          return self if str.nil?

          str.split('.').each do |label|
            self << StructFu::IntString.new(label)
          end
          self << StructFu::IntString.new('')
        end

        # Read a sequence of label from a string
        # @param [String] str binary string
        # @return [Name] self
        def read(str)
          @pointer = nil
          @pointer_name = nil
          clear
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
              label = StructFu::IntString.new('', StructFu::Int8, :parse)
              label.parse(str[start..-1])
              start += label.sz
              self << label
              break if label.len == 0 or str[start..-1].length == 0
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
          str = map(&:string).join('.') + name_from_pointer
          str.empty? ? '.' : str
        end

        # Get options size in bytes
        # @return [Integer]
        def sz
          to_s.size
        end

        private

        def pointer?(index)
          return false if index.nil?
          index & POINTER_MASK == POINTER_MASK
        end

        def name_from_pointer
          return '' unless @pointer
          return @pointer_name if @pointer_name
          
          index = @pointer.unpack('n').first
          mask = ~POINTER_MASK & 0xffff
          ptr = index & mask
          name = Name.new
          name.dns = @dns
          @pointer_name = name.read(self.dns.to_s[ptr..-1]).to_human
        end
      end
    end
  end
end
