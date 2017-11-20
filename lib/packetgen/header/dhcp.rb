# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    
    # Dynamic Host Configuration Protocol, {https://tools.ietf.org/html/rfc2131 
    # RFC 2131}
    # @author Sylvain Daubert
    class DHCP < Base; end

    require_relative 'dhcp/option'
    require_relative 'dhcp/options'

    class DHCP < Base
      # DHCP magic value in BOOTP options
      DHCP_MAGIC = 0x63825363

      define_field :magic, Types::Int32, default: 0x63825563
      define_field :options, DHCP::Options
      
      # differentiate from BOOTP by checking presence of DHCP magic
      # @return [Boolean]
      def parse?
        self.magic == DHCP_MAGIC
      end
    end
    
    BOOTP.bind_header DHCP
  end
end
