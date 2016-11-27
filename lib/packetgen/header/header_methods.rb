module PacketGen
  module Header

    # Mixin for various headers
    # @author Sylvain Daubert
    module HeaderMethods

      # @api private
      # Set reference of packet which owns this header
      # @param [Packet] packet
      # @return [void]
      def packet=(packet)
        @packet = packet
      end

      # @api private
      # Get rference on packet which owns this header
      # @return [Packet]
      def packet
        @packet
      end

      # @api private
      # Get +header+ id in packet headers array
      # @param [Header] header
      # @return [Integer]
      # @raise FormatError +header+ not in a packet
      def header_id(header)
        raise FormatError, "header of type #{header.class} not in a packet" if packet.nil?
        id = packet.headers.index(header)
        if id.nil?
          raise FormatError, "header of type #{header.class} not in packet #{packet}"
        end
        id
      end

      # @api private
      # Get IP or IPv6 previous header from +header+
      # @param [Header] header
      # @return [Header]
      # @raise FormatError no IP or IPv6 header previous +header+ in packet
      # @raise FormatError +header+ not in a packet
      def ip_header(header)
        hid = header_id(header)
        iph = packet.headers[0...hid].reverse.find { |h| h.is_a? IP }
        raise FormatError, 'no IP or IPv6 header in packet' if iph.nil?
        iph
      end
    end
  end
end
