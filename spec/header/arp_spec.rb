require_relative '../spec_helper'

module PacketGen
  module Header

    describe ARP do
      describe '#initialize' do
        it 'creates a ARP header with default values' do
          arp = ARP.new
          expect(arp).to be_a(ARP)
          expect(arp.hw_type).to eq(1)
          expect(arp.proto).to eq(0x800)
          expect(arp.hw_len).to eq(6)
          expect(arp.proto_len).to eq(4)
          expect(arp.opcode).to eq(1)
          expect(arp.src_mac).to eq('00:00:00:00:00:00')
          expect(arp.dst_mac).to eq('00:00:00:00:00:00')
          expect(arp.src_ip).to eq('0.0.0.0')
          expect(arp.dst_ip).to eq('0.0.0.0')
        end

        it 'accepts options' do
          options = {
                     hw_type: 0xf000,
                     proto: 0x1234,
                     hw_len: 255,
                     proto_len: 254,
                     opcode: 0x9999,
                     src_mac: '01:02:03:03:03:03',
                     dst_mac: 'ff:ff:ff:ff:ff:ff',
                     src_ip: '10.0.0.1',
                     dst_ip: '10.0.0.2'
                    }
          arp = ARP.new(options)
          options.each do |key, value|
            expect(arp.send(key)).to eq(value)
          end
        end
      end

      describe '#read' do
        let(:arp) { ARP.new }

        it 'sets header from a string' do
          str = (0...arp.sz).to_a.pack('C*') + 'arp body'
          arp.read str
          expect(arp.hw_type).to eq(0x0001)
          expect(arp.proto).to eq(0x0203)
          expect(arp.hw_len).to eq(0x04)
          expect(arp.proto_len).to eq(0x05)
          expect(arp.opcode).to eq(0x0607)
          expect(arp.src_mac).to eq('08:09:0a:0b:0c:0d')
          expect(arp.src_ip).to eq('14.15.16.17')
          expect(arp.dst_mac).to eq('12:13:14:15:16:17')
          expect(arp.dst_ip).to eq('24.25.26.27')
          expect(arp.body).to eq('arp body')
        end

        it 'raises when str is too short' do
          expect { arp.read 'abcd' }.to raise_error(ParseError, /too short/)
          expect { arp.read('abcdef' * 2) }.to raise_error(ParseError, /too short/)
        end
      end

      describe 'setters' do
        before(:each) do
          @arp = ARP.new
        end

        it '#hw_type= accepts an integer' do
          @arp.hw_type = 0xabcd
          expect(@arp[:hw_type].value).to eq(0xabcd)
        end

        it '#proto= accepts an integer' do
          @arp.proto = 0xabcd
          expect(@arp[:proto].value).to eq(0xabcd)
        end

        it '#hw_len= accepts an integer' do
          @arp.hw_len = 0xab
          expect(@arp[:hw_len].value).to eq(0xab)
        end

        it '#proto_len= accepts an integer' do
          @arp.proto_len = 0xcd
          expect(@arp[:proto_len].value).to eq(0xcd)
        end

        it '#opcode= accepts an integer' do
          @arp.opcode = 0xabcd
          expect(@arp[:opcode].value).to eq(0xabcd)
        end

        it '#src_mac= accepts a MAC address string' do
          @arp.src_mac = 'ff:fe:fd:fc:fb:fa'
          6.times do |i|
            expect(@arp[:src_mac]["a#{i}".to_sym].to_i).to eq(0xff - i)
          end
        end

        it '#dst_mac= accepts a MAC address string' do
          @arp.dst_mac = 'ff:fe:fd:fc:fb:fa'
          6.times do |i|
            expect(@arp[:dst_mac]["a#{i}".to_sym].to_i).to eq(0xff - i)
          end
        end

        it '#src_ip= accepts a IP address string' do
          @arp.src_ip = '128.129.130.131'
          4.times do |i|
            expect(@arp[:src_ip]["a#{i+1}".to_sym].to_i).to eq(128+i)
          end
        end

        it '#dst_ip= accepts a IP address string' do
          @arp.dst_ip = '1.2.3.4'
          4.times do |i|
            expect(@arp[:dst_ip]["a#{i+1}".to_sym].to_i).to eq(1+i)
          end
        end
      end

      it '#to_s returns a binary string' do
        arp = ARP.new(src_mac: '00:1b:11:51:b7:ce', dst_mac: '00:00:00:00:00:00',
                      src_ip: '192.168.1.105', dst_ip: '192.168.1.2')
        expected = "\x00\x01\x08\x00\x06\x04\x00\x01\x00\x1b\x11\x51\xb7\xce" \
          "\xc0\xa8\x01\x69\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\x02"
        PacketGen.force_binary(expected)
        expect(arp.to_s).to eq(expected)
      end
     end
  end
end
