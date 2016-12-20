require_relative '../spec_helper'

module PacketGen
  module Header

    describe ESP do
      describe 'bindings' do
        it 'in IP packets' do
          expect(IP).to know_header(ESP).with(protocol: 50)
        end

        it 'in IPv6 packets' do
          expect(IPv6).to know_header(ESP).with(next: 50)
        end

        it 'in UDP packets' do
          expect(UDP).to know_header(ESP).with(dport: 4500)
          expect(UDP).to know_header(ESP).with(sport: 4500)
        end
      end

      describe '#initialize' do
        it 'creates a ESP header with default values' do
          esp = ESP.new
          expect(esp.icv_length).to eq(0)
          expect(esp.spi).to eq(0)
          expect(esp.sn).to eq(0)
          expect(esp.body).to eq('')
          expect(esp.tfc).to eq('')
          expect(esp.padding).to eq('')
          expect(esp.pad_length).to eq(0)
          expect(esp.next).to eq(0)
          expect(esp.icv).to eq('')
        end

        it 'accepts options' do
          options = {
            icv_length: 16,
            spi: 0x12345678,
            sn: 12,
            body: 'this is a ESP body',
            tfc: "\x00" * 15,
            padding: (1..17).to_a.pack('C*'),
            pad_length: 42,
            next: 4,
            icv: "\x02" * 14
          }
          esp = ESP.new(options)
          options.each do |key, value|
            expect(esp.send(key)).to eq(value)
          end
        end
      end

      describe '#read' do
        let(:esp) { ESP.new }

        it 'sets header from a string' do
          str = (1..esp.sz+16).to_a.pack('C*')
          esp.read str
          expect(esp.spi).to eq(0x01020304)
          expect(esp.sn).to eq(0x05060708)
          expect(esp.body).to eq((9..24).to_a.pack('C*'))
          expect(esp.tfc).to eq('')
          expect(esp.padding).to eq('')
          expect(esp.pad_length).to eq(25)
          expect(esp.next).to eq(26)
          expect(esp.icv).to eq ('')
        end

        it 'also sets ICV when ICV length was previously set' do
          str = (1..esp.sz+16).to_a.pack('C*')
          esp.icv_length = 4
          esp.read str
          expect(esp.spi).to eq(0x01020304)
          expect(esp.sn).to eq(0x05060708)
          expect(esp.body).to eq((9..20).to_a.pack('C*'))
          expect(esp.tfc).to eq('')
          expect(esp.padding).to eq('')
          expect(esp.pad_length).to eq(21)
          expect(esp.next).to eq(22)
          expect(esp.icv).to eq("\x17\x18\x19\x1a")
        end

        it 'raises when str is too short' do
          str = (1..(esp.sz-1))
          expect { esp.read str }.to raise_error(ParseError, 'string too short for ESP')
        end
      end

      describe 'setters' do
        let(:esp) { ESP.new }

        it '#spi= accepts integers' do
          esp.spi = 12345678
          expect(esp[:spi].to_i).to eq(12345678)
        end

        it '#sn= accepts integers' do
          esp.sn = 0x87654321
          expect(esp[:sn].to_i).to eq(0x87654321)
        end

        it '#pad_length= accepts integers' do
          esp.pad_length = 255
          expect(esp[:pad_length].to_i).to eq(255)
        end

        it '#next= accepts integers' do
          esp.next = 128
          expect(esp[:next].to_i).to eq(128)
        end

      end

      describe '#to_s' do
        it 'returns a binary string' do
          esp = ESP.new
          esp.body = 'body'
          esp.spi = 1
          esp.sn = 2
          expected = [1, 2].pack('N2') + 'body' + "\x00" * 2
          expect(esp.to_s).to eq(PacketGen.force_binary expected)
        end
      end
      
      describe '#inspect' do
        it 'returns a String with all attributes' do
          esp = ESP.new
          str = esp.inspect
          expect(str).to be_a(String)
          (esp.members - %i(body)).each do |attr|
            expect(str).to include(attr.to_s)
          end
        end
      end

      describe '#encrypt!' do
        it 'encrypts a payload with CBC mode'
        it 'encryts a payload with CTR mode and authenticates it with HMAC-SHA256'
        it 'encrypts and authenticates a payload with GCM mode'
        it 'encrypts a payload with TFC'
        it 'encrypts a payload with Extended SN'
        it 'encrypts a payload with given padding'
        it 'encrypts a payload with given padding length'
        it 'encrypts a payload with given padding and padding length'
      end

      describe '#decrypt!' do
        it 'decrypts a payload with CBC mode'
        it 'decryts a payload with CTR mode and authenticates it with HMAC-SHA256'
        it 'decrypts and authenticates a payload with GCM mode'
        it 'decrypts a payload with TFC'
        it 'decrypts a payload with Extended SN'
        it 'decrypts a payload without parsing it'
      end
    end
  end
end