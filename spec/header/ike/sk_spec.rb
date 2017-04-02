require_relative '../../spec_helper'

module PacketGen
  module Header
    class IKE
      describe SK do
        describe '#initialize' do
          it 'creates a SK payload with default values' do
            sk = SK.new
            expect(sk.next).to eq(0)
            expect(sk.flags).to eq(0)
            expect(sk.length).to eq(4)
            expect(sk.content).to be_empty
          end

          it 'accepts options' do
            opts = {
              next: 59,
              flags: 0x65,
              length: 128,
              content: 'abcdefghij'
            }

            sk = SK.new(opts)
            opts.each do |k,v|
              expect(sk.send(k)).to eq(v)
            end
          end
        end

        describe '#read' do
          it 'sets SK from a binary string' do
            str = [12, 0x80, 25, 'z' * 13].pack('CCnA*')
            sk = SK.new.read(str)
            expect(sk.next).to eq(12)
            expect(sk.flags).to eq(0x80)
            expect(sk.critical?).to be(true)
            expect(sk.hreserved).to eq(0)
            expect(sk.length).to eq(25)
            expect(sk.content).to eq('z' * 13)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            sk = SK.new(next: 2, content: 'abcdefghijkl')
            sk.calc_length
            expected = "\x02\x00\x00\x10abcdefghijkl"
            expect(sk.to_s).to eq(PacketGen.force_binary expected)
          end
        end

        describe '#inspect' do
          it 'returns a string with all attributes' do
            sk = SK.new
            str = sk.inspect
            expect(str).to be_a(String)
            (sk.fields - %i(body)).each do |attr|
               expect(str).to include(attr.to_s)
             end
          end
        end

        context 'crypto' do
          let (:sk_ei) { ['B37E73D129FFE681D2E3AA3728C2401E' \
                          'D50160E39FD55EF1A1EAE0D3F4AA6126D8B8A626'].pack('H*') }
          let (:pkt) { PacketGen.read(File.join(__dir__, '..', 'ikev2.pcapng'))[2] }
          let (:cipher) { get_cipher('gcm', :decrypt, sk_ei[0..31]) }

          describe '#decrypt!' do
            it 'decrypts a GCM-encrypted SK payload' do
              expect(pkt.ike_sk.decrypt! cipher, salt: sk_ei[32..35],
                                         icv_length: 16).to be(true)
              expect(pkt.ike.payloads.size).to eq(12)
            end

            it 'returns false on bad ICV' do
              pkt.ike_sk.content[-1] = PacketGen.force_binary("\xff")
              pkt.ike_sk.icv_length = 16
              expect(pkt.ike_sk.decrypt! cipher, salt: sk_ei[32..35]).to be(false)
            end
          end

          describe '#encrypt!' do
            it 'encrypts a SK payload with GCM mode' do
              cipher = get_cipher('gcm', :decrypt, sk_ei[0..31])
              pkt.ike_sk.decrypt! cipher, salt: sk_ei[32..35], icv_length: 16

              cipher = get_cipher('gcm', :encrypt, sk_ei[0..31])
              iv = ['61c37f461d9fce57'].pack('H*')
              pkt.ike_sk.encrypt! cipher, iv, salt: sk_ei[32..35]
              expect(pkt.to_s).to eq(PacketGen.read(File.join(__dir__, '..',
                                                              'ikev2.pcapng'))[2].to_s)
            end
          end
        end
      end
    end
  end
end

