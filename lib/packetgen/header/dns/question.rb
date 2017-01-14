module PacketGen
  module Header
    class DNS

      # DNS Question
      # @author Sylvain Daubert
      class Question < Struct.new(:name, :type, :rrclass)
        include StructFu
        include BaseRR

        # Question types
        TYPES = RR::TYPES.merge({ '*' => 255 })

        # Question classes
        CLASSES = RR::CLASSES.merge({ 'NONE' => 254, '*' => 255 })

        # @param [DNS] dns
        # @param [Hash] options
        # @option options [String] :name domain as a dotted string
        # @option options [Integer,String] :type see {TYPES}. Default to +'A'+
        # @option options [Integer,String] :rrclass see {CLASSES}. Default to +'IN'+
        def initialize(dns, options={})
          super Name.new(dns).parse(options[:name]),
                Int16.new,
                Int16.new
          self.type = options[:type] || 'A'
          self.rrclass = options[:rrclass] || 'IN'
        end

        # Read DNS question from a string
        # @param [String] str binary string
        # @return [self]
        def read(str)
          return self if str.nil?
          force_binary str
          self[:name].read str
          self[:type].read str[self[:name].sz, 2]
          self[:rrclass].read str[self[:name].sz+2, 2]
          self
        end

        alias qname name
        alias qname= name=
        alias qtype type
        alias qtype= type=
        alias qclass rrclass
        alias qclass= rrclass=

        # @return [String]
        def to_human
          "#{human_type} #{human_rrclass} #{name.to_human}"
        end
      end
    end
  end
end
