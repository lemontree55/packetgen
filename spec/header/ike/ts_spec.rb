require_relative '../../spec_helper'

module PacketGen
  module Header
    class IKE
      describe TrafficSelector do
        let(:ts) { TrafficSelector.new }

        describe '#initialize' do
          it 'creates a TrafficSelector with default values' do
            ts = TrafficSelector.new
            expect(ts.type).to eq(7)
            expect(ts.human_type).to eq('IPv4')
            expect(ts.protocol).to eq(0)
            expect(ts.length).to eq(16)
            expect(ts.start_port).to eq(0)
            expect(ts.end_port).to eq(65535)
            expect(ts.start_addr).to eq('0.0.0.0')
            expect(ts.end_addr).to eq('0.0.0.0')
          end

          it 'accepts options' do
            options = {
              type: TrafficSelector::TS_IPV6_ADDR_RANGE,
              protocol: 58,
              length: 0x100,
              start_port: 0x8000,
              end_port: 0x8100,
              start_addr: '10::1',
              end_addr: '31::'
            }

            ts = TrafficSelector.new(options)
            options.each do |k,v|
              expect(ts.send(k)).to eq(v)
            end
          end

          it 'accepts ports option' do
            ts = TrafficSelector.new(ports: 1025..3000)
             expect(ts.start_port).to eq(1025)
             expect(ts.end_port).to eq(3000)
          end

          it 'guesses type from addresses' do
            ts = TrafficSelector.new(start_addr: '10.0.0.1', end_addr: '31.255.255.255')
            expect(ts.human_type).to eq('IPv4')
            expect(ts[:start_addr]).to be_a(IP::Addr)
            expect(ts[:end_addr]).to be_a(IP::Addr)
            ts = TrafficSelector.new(start_addr: '10::1', end_addr: '11::0')
            expect(ts.human_type).to eq('IPv6')
            expect(ts[:start_addr]).to be_a(IPv6::Addr)
            expect(ts[:end_addr]).to be_a(IPv6::Addr)
          end
        end

        describe '#read' do
          it 'sets TrafficSelector from a binary string (IPv4)' do
            str = [7, 6, 16, 0, 65535, 10, 0, 0, 1, 10, 0, 0, 255].pack('CCnnnC8')
            ts.read(str)
            expect(ts.human_type).to eq('IPv4')
            expect(ts.human_protocol).to eq('tcp')
            expect(ts.length).to eq(16)
            expect(ts.start_port).to eq(0)
            expect(ts.end_port).to eq(65535)
            expect(ts.start_addr).to eq('10.0.0.1')
            expect(ts.end_addr).to eq('10.0.0.255')
          end

          it 'sets TrafficSelector from a binary string (IPv6)' do
            str = [8, 17, 40, 443, 443].pack('CCn3')
            str << ([0] * 15 + [1] + [0] * 14 + [65535]).pack('C30n')
            ts.read(str)
            expect(ts.human_type).to eq('IPv6')
            expect(ts.human_protocol).to eq('udp')
            expect(ts.length).to eq(40)
            expect(ts.start_port).to eq(443)
            expect(ts.end_port).to eq(443)
            expect(ts.start_addr).to eq('::1')
            expect(ts.end_addr).to eq('::ffff')
          end
        end

        describe '#type=' do
          it 'accepts Integer' do
            ts.type = 8
            expect(ts.type).to eq(8)
            ts.type = 7
            expect(ts.type).to eq(7)
          end

          it 'accepts String' do
            ts.type = 'IPV4'
            expect(ts.type).to eq(7)
            ts.type = 'IPv4'
            expect(ts.type).to eq(7)
            ts.type = 'ipv4'
            expect(ts.type).to eq(7)
            ts.type = 'IPV6'
            expect(ts.type).to eq(8)
            ts.type = 'IPv6'
            expect(ts.type).to eq(8)
            ts.type = 'ipv6'
            expect(ts.type).to eq(8)
          end

          it 'raises on unknown type' do
            expect { ts.type = 48 }.to raise_error(ArgumentError, /unknown type/)
            expect { ts.type = 'blah!' }.to raise_error(ArgumentError, /unknown type/)
          end
        end

        describe '#protocol=' do
          it 'accepts Integer' do
            ts.protocol = 250
            expect(ts.protocol).to eq(250)
            expect(ts.human_protocol).to eq('250')
          end

          it 'accepts String' do
            ts.protocol = 'ospf'
            expect(ts.protocol).to eq(89)
            expect(ts.human_protocol).to eq('ospf')
          end

          it 'raises on unknown protocol (String only)' do
            expect { ts.protocol = 'blah!' }.to raise_error(ArgumentError,
                                                            /unknown protocol/)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            ts = TrafficSelector.new(protocol: 'igmp', start_addr: '42.23.5.89',
                                     end_addr: '42.23.5.89')
            expected = "\x07\x02\x00\x10\x00\x00\xff\xff\x2a\x17\x05\x59\x2a\x17\x05\x59"
            expect(ts.to_s).to eq(PacketGen.force_binary expected)

            ts = TrafficSelector.new(protocol: 'sctp', ports: 64..65,
                                     start_addr: '2a00::1', end_addr: '2a00::2')
            expected = "\x08\x84\x00\x28\x00\x40\x00\x41"
            expected << IPAddr.new('2a00::1').hton << IPAddr.new('2a00::2').hton
            expect(ts.to_s).to eq(PacketGen.force_binary expected)
          end
        end

        describe '#to_human' do
          it 'returns a human readable string' do
            ts = TrafficSelector.new(protocol: 'igmp', start_addr: '42.23.5.89',
                                     end_addr: '42.23.5.89')
            expect(ts.to_human).to eq('42.23.5.89-42.23.5.89/igmp')
            ts = TrafficSelector.new(protocol: 'sctp', ports: 64..65,
                                     start_addr: '2a00::1', end_addr: '2a00::2')
            expect(ts.to_human).to eq('2a00::1-2a00::2/sctp[64-65]')
          end
        end
      end

      describe TSi do
        describe '#initialize' do
          it 'creates a TSi payload with default values' do
            tsi = TSi.new
            expect(tsi.next).to eq(0)
            expect(tsi.flags).to eq(0)
            expect(tsi.length).to eq(8)
            expect(tsi.num_ts).to eq(0)
            expect(tsi.traffic_selectors).to be_empty
          end

          it 'accepts options' do
            opts = {
              next: 59,
              flags: 0x65,
              length: 128,
              num_ts: 0xf0,
            }

            tsi = TSi.new(opts)
            opts.each do |k,v|
              expect(tsi.send(k)).to eq(v)
            end
          end
        end

        describe '#read' do
          it 'sets TSi from a binary string' do
            sk_ei = ['B37E73D129FFE681D2E3AA3728C2401E' \
                     'D50160E39FD55EF1A1EAE0D3F4AA6126D8B8A626'].pack('H*')
            cipher = get_cipher('gcm', :decrypt, sk_ei[0..31])
            pkt = PacketGen.read(File.join(__dir__, '..', 'ikev2.pcapng'))[2]
            pkt.ike_sk.decrypt! cipher, salt: sk_ei[32..35], icv_length: 16, parse: false
            str = pkt.ike_sk.body
            idx =  str.index(PacketGen.force_binary "\x2d\x00\x00\x18")
            tsi = TSi.new.read(str[idx, 0x18])
            expect(tsi.next).to eq(45)
            expect(tsi.flags).to eq(0)
            expect(tsi.length).to eq(24)
            expect(tsi.num_ts).to eq(1)
            expect(tsi.rsv1).to eq(0)
            expect(tsi.rsv2).to eq(0)
            expect(tsi.selectors.to_human).to eq('10.1.0.0-10.1.0.255')
            expect(tsi.selectors.first.human_protocol).to eq('')
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            tsi = TSi.new(next: 2, num_ts: 22)
            tsi.calc_length
            expected = "\x02\x00\x00\x08\x16\x00\x00\x00"
            expect(tsi.to_s).to eq(PacketGen.force_binary expected)
          end
        end

        describe '#inspect' do
          it 'returns a string with all attributes' do
            tsi = TSi.new
            str = tsi.inspect
            expect(str).to be_a(String)
            (tsi.fields - %i(body rsv1 rsv2)).each do |attr|
               expect(str).to include(attr.to_s)
             end
          end
        end

        describe '#traffic_selectors' do
          let(:tsi) { TSi.new }
          it 'accepts pushing a TrafficSelector object' do
            ts = TrafficSelector.new(type: 7, start_addr: '10.0.0.1',
                                     end_addr: '10.0.0.255')
            expect { tsi.selectors << ts }.to change { tsi.num_ts }.by(1)
          end

          it 'accepts pushing a Hash describing a traffic selector' do
            expect { tsi.selectors << { type: 'IPv4', start_addr: '10.0.0.1',
                                        end_addr: '10.0.0.255', protocol: 'tcp',
                                        ports: 1..1024 } }.
              to change { tsi.num_ts }.by(1)
          end

          it 'accepts pushing a Hash describing a traffic selector, guessing type' do
            expect { tsi.selectors << { start_addr: '10.0.0.1',
                                        end_addr: '10.0.0.255', protocol: 'tcp',
                                        ports: 1..1024 } }.
              to change { tsi.num_ts }.by(1)
            expect(tsi.selectors.last.human_type).to eq('IPv4')
            expect(tsi.selectors.last.start_port).to eq(1)
            expect(tsi.selectors.last.end_port).to eq(1024)

            expect { tsi.selectors << { start_addr: '2001::1',
                                        end_addr: '2002::' } }.
              to change { tsi.num_ts }.by(1)
            expect(tsi.selectors.last.type).to eq(TrafficSelector::TS_IPV6_ADDR_RANGE)
            expect(tsi.selectors.last.start_addr).to eq('2001::1')
            expect(tsi.selectors.last.end_addr).to eq('2002::')
          end
        end
      end
    end
  end
end
