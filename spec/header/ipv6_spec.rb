require_relative '../spec_helper'

module PacketGen
  module Header

    describe IPv6::Addr do
      before(:each) do
        @ipv6addr = IPv6::Addr.new.parse('fe80::21a:c5ff:fe00:152')
      end

      it '#parse a string containing a dotted address' do
        expect(@ipv6addr.a1).to eq(0xfe80)
        expect(@ipv6addr.a2).to eq(0)
        expect(@ipv6addr.a3).to eq(0)
        expect(@ipv6addr.a4).to eq(0)
        expect(@ipv6addr.a5).to eq(0x021a)
        expect(@ipv6addr.a6).to eq(0xc5ff)
        expect(@ipv6addr.a7).to eq(0xfe00)
        expect(@ipv6addr.a8).to eq(0x0152)
      end

      it '#to_x returns a dotted address as String' do
        expect(@ipv6addr.to_x).to eq('fe80::21a:c5ff:fe00:152')
      end

      it '#read gets a IPv6 address from a binary string' do
        bin_str = "\xfe\x80" << "\x00" * 6 << "\x02\x1a\xc5\xff\xfe\x00\x01\x52"
        ipv6addr = IPv6::Addr.new.read(bin_str)
        expect(ipv6addr.to_x).to eq('fe80::21a:c5ff:fe00:152')
      end
    end

    describe IPv6 do
    end
  end
end
