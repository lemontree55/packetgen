# frozen_string_literal: true

require_relative '../spec_helper'

module PacketGen
  module Header
    describe MDNS do
      let(:mdns_raw_packets) { read_raw_packets('mdns.pcapng') }

      describe 'binding' do
        it 'in UDP packets' do
          expect(UDP).to know_header(MDNS).with(sport: 5353)
          expect(UDP).to know_header(MDNS).with(dport: 5353)
        end

        it 'accepts to be added in UDP packets' do
          pkt = PacketGen.gen('UDP')
          expect { pkt.add('MDNS') }.not_to raise_error
          expect(pkt.udp.dport).to eq(5353)
        end
      end

      context 'with sections' do
        let(:dns) { MDNS.new }

        it 'may add a Question to question section' do
          q = DNS::Question.new(dns, name: 'www.example.org')
          expect { dns.qd << q }.to change(dns, :qdcount).by(1)
          expected_str = "\x00".b * 5 << "\x01".b << "\x00".b * 6 <<
                         generate_label_str(%w[www example org]) <<
                         "\x00\x01\x00\x01".b
          expect(dns.to_s).to eq(expected_str)
        end

        it 'may add a RR to answer section' do
          an = DNS::RR.new(dns, name: 'www.example.org', type: 'AAAA', ttl: 3600,
                                rdata: IPAddr.new('2000::1').hton)
          expect { dns.an << an }.to change(dns, :ancount).by(1)
          expected_str = "\x00".b * 7 + "\x01".b + "\x00".b * 4 +
                         generate_label_str(%w[www example org]) +
                         "\x00\x1c\x00\x01\x00\x00\x0e\x10\x00\x10\x20".b +
                         "\x00".b * 14 + "\x01".b
          expect(dns.to_s).to eq(expected_str)
        end
      end

      describe '#read' do
        it 'reads a mDNS question header' do
          pkt = Packet.parse(mdns_raw_packets[0])
          expect(pkt.is?('MDNS')).to be(true)

          mdns = pkt.mdns
          expect(mdns.qr?).to be(false)
          expect(mdns.qdcount).to eq(2)
          expect(mdns.ancount).to eq(0)
          expect(mdns.nscount).to eq(2)
          expect(mdns.arcount).to eq(0)

          expect(mdns.qd[0].to_human).to eq('* IN QU Host-002.local.')
          expect(mdns.qd[1].to_human).to eq('* IN QU Officejet 6500 E710n-z [B25D97]._pdl-datastream._tcp.local.')

          expect(mdns.ns[0].to_human).to eq('A IN Host-002.local. TTL 120 192.168.0.96')
          expect(mdns.ns[1].to_human).to eq('SRV IN Officejet 6500 E710n-z [B25D97]._pdl-datastream._tcp.local. TTL 120 0 0 9100 Host-002.local.')
        end

        it 'reads a mDNS question header' do
          pkt = Packet.parse(mdns_raw_packets[1])
          expect(pkt.is?('MDNS')).to be(true)

          mdns = pkt.mdns
          expect(mdns.qr?).to be(true)
          expect(mdns.qdcount).to eq(0)
          expect(mdns.ancount).to eq(5)
          expect(mdns.nscount).to eq(0)
          expect(mdns.arcount).to eq(0)

          expect(mdns.an[0].to_human).to eq('A IN CACHE-FLUSH Host-002.local. TTL 120 192.168.0.96')
          expect(mdns.an[1].to_human).to eq('PTR IN CACHE-FLUSH 96.0.168.192.in-addr.arpa. TTL 120 Host-002.local.')
          expect(mdns.an[2].to_human).to eq('SRV IN CACHE-FLUSH Officejet 6500 E710n-z [B25D97]._pdl-datastream._tcp.local. TTL 120 0 0 9100 Host-002.local.')
        end
      end

      describe '#mdnsize' do
        context '(IPv4)' do
          let(:pkt) { Packet.gen('Eth').add('IP').add('UDP').add('MDNS') }

          it 'sets Ethernet destination address' do
            pkt.mdnsize
            expect(pkt.eth.dst).to eq('01:00:5e:00:00:fb')
          end

          it 'sets IP destination address' do
            pkt.mdnsize
            expect(pkt.ip.dst).to eq('224.0.0.251')
          end
        end

        context '(IPv6)' do
          let(:pkt) { Packet.gen('Eth').add('IPv6').add('UDP').add('MDNS') }

          it 'sets Ethernet destination address' do
            pkt.mdnsize
            expect(pkt.eth.dst).to eq('33:33:00:00:00:fb')
          end

          it 'sets IPv6 destination address' do
            pkt.mdnsize
            expect(pkt.ipv6.dst).to eq('ff02::fb')
          end
        end
      end
    end
  end
end
