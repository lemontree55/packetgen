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

      context 'crypto' do
        let(:key) { (0..15).to_a.pack('C*') }
        let(:hmac_key) { (16..31).to_a.pack('C*') }
        let(:salt) { [0x80818283].pack('N') }

        describe '#encrypt!' do

          it 'encrypts a payload with CBC mode' do
            esp_pkt, red_pkt = get_packets_from(File.join(__dir__, 'esp4-cbc.pcapng'))

            black_pkt = Packet.gen('IP').add('ESP', spi: 0x87654321, sn: 2)
            black_pkt.encapsulate red_pkt
            esp = black_pkt.esp

            cipher = get_cipher('cbc', :encrypt, key)
            iv = [0xbc, 0x4d, 0x73, 0x4b, 0x8d, 0x84, 0xa0, 0x3b,
                  0x12, 0xa7, 0xf7, 0xdf, 0xee, 0xaa, 0x82, 0x27].pack('C*')
            esp.encrypt! cipher, iv
            expect(esp.to_s).to eq(esp_pkt.esp.to_s)
          end

          it 'encryts a payload with CTR mode and authenticates it with HMAC-SHA256' do
            esp_pkt, red_pkt = get_packets_from(File.join(__dir__, 'esp4-ctr-hmac.pcapng'),
                                                icv_length: 12)

            black_pkt = Packet.gen('IP').add('ESP', spi: 0x87654321, sn: 4,
                                             icv_length: 12)
            black_pkt.encapsulate red_pkt
            esp = black_pkt.esp

            cipher = get_cipher('ctr', :encrypt, key)
            hmac = OpenSSL::HMAC.new(hmac_key, OpenSSL::Digest::SHA256.new)

            iv = [0x2d, 0x28, 0x32, 0xfb, 0xb2, 0x7c, 0x95, 0x30].pack('C*')
            esp.encrypt! cipher, iv, salt: salt, intmode: hmac
            expect(esp.to_s).to eq(esp_pkt.esp.to_s)
          end

          it 'encrypts and authenticates a payload with GCM mode' do
            esp_pkt, red_pkt = get_packets_from(File.join(__dir__, 'esp4-gcm.pcapng'),
                                                icv_length: 16)

            black_pkt = Packet.gen('IP').add('ESP', spi: 0x87654321, sn: 2,
                                             icv_length: 16)
            black_pkt.encapsulate red_pkt
            esp = black_pkt.esp

            cipher = get_cipher('gcm', :encrypt, key)
            iv = [0x4d, 0xb4, 0xb2, 0x00, 0xe7, 0x72, 0x5e, 0x57].pack('C*')
            esp.encrypt! cipher, iv, salt: salt
            expect(esp.to_s).to eq(esp_pkt.esp.to_s)
          end

          it 'encrypts a payload with TFC'
          it 'encrypts a payload with Extended SN'
          it 'encrypts a payload with given padding'
          it 'encrypts a payload with given padding length'
          it 'encrypts a payload with given padding and padding length'
        end

        describe '#decrypt!' do
          it 'decrypts a payload with CBC mode' do
            pkt, red_pkt = get_packets_from(File.join(__dir__, 'esp4-cbc.pcapng'))

            
            cipher = get_cipher('cbc', :decrypt, key)
            expect(pkt.esp.decrypt!(cipher)).to be(true)
            pkt.decapsulate pkt.ip, pkt.esp
            expect(pkt.to_s).to eq(red_pkt.to_s)
          end

          it 'decryts a payload with CTR mode and authenticates it with HMAC-SHA256' do
            pkt, red_pkt = get_packets_from(File.join(__dir__, 'esp4-ctr-hmac.pcapng'),
                                            icv_length: 12)

            cipher = get_cipher('ctr', :decrypt, key)
            hmac = OpenSSL::HMAC.new(hmac_key, OpenSSL::Digest::SHA256.new)

            expect(pkt.esp.decrypt!(cipher, salt: salt, intmode: hmac)).to be(true)
            pkt.decapsulate pkt.ip, pkt.esp
            expect(pkt.to_s).to eq(red_pkt.to_s)
          end

          it 'decrypts and authenticates a payload with GCM mode' do
            pkt, red_pkt = get_packets_from(File.join(__dir__, 'esp4-gcm.pcapng'),
                                            icv_length: 16)

            cipher = get_cipher('gcm', :decrypt, key)
            expect(pkt.esp.decrypt!(cipher, salt: salt)).to be(true)
            pkt.decapsulate pkt.ip, pkt.esp
            expect(pkt.to_s).to eq(red_pkt.to_s)
          end

          it 'decrypts a payload with TFC'
          it 'decrypts a payload with Extended SN'
          it 'decrypts a payload without parsing it'

          it 'returns false when ICV check failed' do
            pkt, = get_packets_from(File.join(__dir__, 'esp4-ctr-hmac.pcapng'),
                                    icv_length: 12)
            cipher = get_cipher('ctr', :decrypt, key)
            hmac = OpenSSL::HMAC.new(hmac_key, OpenSSL::Digest::SHA256.new)
            pkt.esp.icv[-1] = "\x00"
            expect(pkt.esp.decrypt!(cipher, salt: salt, intmode: hmac)).to be(false)

            pkt, = get_packets_from(File.join(__dir__, 'esp4-gcm.pcapng'),
                                    icv_length: 16)
            pkt.esp.body[16] = "\x00"
            cipher = get_cipher('gcm', :decrypt, key)
            expect(pkt.esp.decrypt!(cipher, salt: salt)).to be(false)
          end
        end
      end
    end
  end
end
