module PacketGen
  module Header

    # TCP header class
    # @author Sylvain Daubert
    class TCP < Struct.new(:sport, :dport, :seq, :ack, :hlen, :reserved,
                           :flags, :wsize, :sum, :urg, :options, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # IP protocol number for TCP
      IP_PROTOCOL = 6

      def initialize(options={})
      end

      def read(str)
      end

      def calc_sum
      end

      def calc_length
      end
    end
  end
end
