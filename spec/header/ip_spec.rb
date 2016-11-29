require_relative '../spec_helper'

module PacketGen
  module Header

    describe IP::Addr do
      before(:each) do
        @ipaddr = IP::Addr.new.parse('192.168.25.43')
      end

      it '#parse a string containing a dotted address' do
        expect(@ipaddr.a1).to eq(192)
        expect(@ipaddr.a2).to eq(168)
        expect(@ipaddr.a3).to eq(25)
        expect(@ipaddr.a4).to eq(43)
      end

      it '#to_i gets IP address as a 32-bit integer' do
        expect(@ipaddr.to_i).to eq(0xc0a8192b)
      end

      it '#to_x returns a dotted address as String' do
        expect(@ipaddr.to_x).to eq('192.168.25.43')
      end
    end

    describe IP do

      describe 'binding' do
        it 'in Eth packets' do
          expect(Eth.known_headers[IP].to_h).to eq({key: :proto, value: 0x800})
        end
        it 'in IP packets' do
          expect(IP.known_headers[IP].to_h).to eq({key: :proto, value: 4})
        end
      end

      describe '#initialize' do
        it 'creates a IP header with default values' do
          ip = IP.new
          expect(ip).to be_a(IP)
          expect(ip.version).to eq(4)
          expect(ip.tos).to eq(0)
          expect(ip.len).to eq(20)
          expect(ip.id).to be < 65536
          expect(ip.frag).to eq(0)
          expect(ip.ttl).to eq(64)
          expect(ip.proto).to eq(0)
          expect(ip.sum).to eq(0)
          expect(ip.src).to eq('127.0.0.1')
          expect(ip.dst).to eq('127.0.0.1')
          expect(ip.body).to eq('')
        end

        it 'accepts options' do
          options = {
            version: 15,
            ihl: 15,
            tos: 255,
            len: 1000,
            id: 153,
            frag: 0x4000,
            ttl: 2,
            proto: 250,
            sum: 1,
            src: '1.1.1.1',
            dst: '2.2.2.2',
            body: 'this is a body'
          }
          ip = IP.new(options)
          options.each do |key, value|
            expect(ip.send(key)).to eq(value)
          end
        end

      describe '#read' do
        let(:ip) { IP.new}

        it 'sets header from a string' do
          str = (1..ip.sz).to_a.pack('C*') + 'body'
          ip.read str
          expect(ip.version).to eq(0)
          expect(ip.ihl).to eq(1)
          expect(ip.tos).to eq(2)
          expect(ip.len).to eq(0x0304)
          expect(ip.id).to eq(0x0506)
          expect(ip.frag).to eq(0x0708)
          expect(ip.ttl).to eq(9)
          expect(ip.proto).to eq(10)
          expect(ip.sum).to eq(0x0b0c)
          expect(ip.src).to eq('13.14.15.16')
          expect(ip.dst).to eq('17.18.19.20')
          expect(ip.body).to eq('body')
        end

        it 'raises when str is too short' do
          expect { ip.read 'abcd' }.to raise_error(ParseError, /too short/)
          expect { ip.read('a' * 18) }.to raise_error(ParseError, /too short/)
        end
      end

        describe '#calc_sum' do
          it 'compute IP header checksum' do
            ip = IP.new(len: 60, id: 0x1c46, frag: 0x4000, ttl: 64, proto: 6,
                        src: '172.16.10.99', dst: '172.16.10.12')
            ip.calc_sum
            expect(ip.sum).to eq(0xb1e6)
          end
        end

        describe 'setters' do
          before(:each) do
            @ip = IP.new
          end

          it '#tos= accepts integers' do
            @ip.tos = 254
            expect(@ip[:tos].to_i).to eq(254)
          end

          it '#len= accepts integers' do
            @ip.len = 0xff10
            expect(@ip[:len].to_i).to eq(0xff10)
          end

          it '#id= accepts integers' do
            @ip.id = 0x8001
            expect(@ip[:id].to_i).to eq(0x8001)
          end

          it '#frag= accepts integers' do
            @ip.frag = 0x4001
            expect(@ip[:frag].to_i).to eq(0x4001)
          end

          it '#ttl= accepts integers' do
            @ip.ttl = 255
            expect(@ip[:ttl].to_i).to eq(255)
          end

          it '#proto= accepts integers' do
            @ip.proto = 255
            expect(@ip[:proto].to_i).to eq(255)
          end

          it '#sum= accepts integers' do
            @ip.sum = 0xf00f
            expect(@ip[:sum].to_i).to eq(0xf00f)
          end

          it '#src= accepts dotted addresses' do
            @ip.src = '1.2.3.4'
            1.upto(4) do |i|
              expect(@ip[:src]["a#{i}".to_sym].to_i).to eq(i)
            end
            expect(@ip[:src].to_i).to eq(0x01020304)
          end

          it '#dst= accepts dotted addresses' do
            @ip.dst = '1.2.3.4'
            1.upto(4) do |i|
              expect(@ip[:dst]["a#{i}".to_sym].to_i).to eq(i)
            end
            expect(@ip[:dst].to_i).to eq(0x01020304)
          end
        end

        it '#to_s returns a binary string' do
          ip = IP.new
          idx = [ip.id].pack('n')
          expect(ip.to_s).to eq("\x45\x00\x00\x14#{idx}\x00\x00\x40\x00\x00\x00" \
                                "\x7f\x00\x00\x01\x7f\x00\x00\x01")
        end
      end
    end
  end
end
