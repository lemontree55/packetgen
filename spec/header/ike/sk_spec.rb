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
            expect(sk.to_s).to eq(force_binary expected)
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
          let(:cbc_sk_ei) { ['27A29D9516D8B657E4501D499CA35484'].pack('H*') }
          let(:hmac_sk_ai) { ['8DAD540E7B992063CE893021DBF48051' \
                              'BA669F79B608FAB021742129AF192AD5'].pack('H*') }
          let(:cbc_pkt) { PacketGen.read(File.join(__dir__, '..', 'ikev2_cbc_hmac.pcapng'))[2] }
          let(:cbc_cipher) { get_cipher('cbc', :decrypt, cbc_sk_ei) }
          let(:hmac) { OpenSSL::HMAC.new(hmac_sk_ai, OpenSSL::Digest::SHA256.new) }

          let(:gcm_sk_ei) { ['B37E73D129FFE681D2E3AA3728C2401E' \
                             'D50160E39FD55EF1A1EAE0D3F4AA6126D8B8A626'].pack('H*') }
          let(:gcm_pkt) { PacketGen.read(File.join(__dir__, '..', 'ikev2.pcapng'))[2] }
          let(:gcm_cipher) { get_cipher('gcm', :decrypt, gcm_sk_ei[0..31]) }

          describe '#decrypt!' do
            it 'decrypts a CBC-encrypted HMAC-SHA256-authenticated SK payload' do
              expect(cbc_pkt.ike_sk.decrypt! cbc_cipher, intmode: hmac, icv_length: 16).
                to be(true)
              expect(cbc_pkt.ike.payloads.size).to eq(11)
            end

            it 'decrypts a CTR-encrypted HMAC-SHA256-authenticated SK payload'

            it 'decrypts a GCM-encrypted SK payload' do
              expect(gcm_pkt.ike_sk.decrypt! gcm_cipher, salt: gcm_sk_ei[32..35],
                                             icv_length: 16).to be(true)
              expect(gcm_pkt.ike.payloads.size).to eq(12)
            end

            it 'returns false on bad ICV' do
              cbc_pkt.ike_sk.content[-17] = force_binary("\xff")
              cbc_pkt.ike_sk.icv_length = 16
              expect(cbc_pkt.ike_sk.decrypt! cbc_cipher, intmode: hmac).to be(false)
            end

            it 'returns false on bad ICV (combined mode)' do
              gcm_pkt.ike_sk.content[-1] = force_binary("\xff")
              gcm_pkt.ike_sk.icv_length = 16
              expect(gcm_pkt.ike_sk.decrypt! gcm_cipher, salt: gcm_sk_ei[32..35]).
                to be(false)
            end

            it 'raises on authenticated cipher without icv_length being set' do
              salt = "\x00" * 4
              expect { gcm_pkt.ike_sk.decrypt! gcm_cipher, salt: salt }.
                to raise_error(ParseError, 'unknown ICV size')
            end
          end

          describe '#encrypt!' do
            it 'encrypts and authenticates a SK payload with CBC and HMAC-SHA256' do
              cbc_pkt.ike_sk.decrypt! cbc_cipher, intmode: hmac, icv_length: 16

              cipher = get_cipher('cbc', :encrypt, cbc_sk_ei)
              iv = ['73a78d120e20568e9ed9cfb66f1e1d42'].pack('H*')
              padding = ['734ee746bd36'].pack('H*')
              cbc_pkt.ike_sk.encrypt! cipher, iv, intmode: hmac, padding: padding
              expected_pkt = PacketGen.read(File.join(__dir__, '..',
                                                      'ikev2_cbc_hmac.pcapng'))[2]
              expect(cbc_pkt.to_s).to eq(expected_pkt.to_s)
            end

            it 'encrypts and authenticates a SK payload with CTR and HMAC-SHA256'

            it 'encrypts a SK payload with GCM mode' do
              gcm_pkt.ike_sk.decrypt! gcm_cipher, salt: gcm_sk_ei[32..35], icv_length: 16

              cipher = get_cipher('gcm', :encrypt, gcm_sk_ei[0..31])
              iv = ['61c37f461d9fce57'].pack('H*')
              gcm_pkt.ike_sk.encrypt! cipher, iv, salt: gcm_sk_ei[32..35]
              expected_pkt = PacketGen.read(File.join(__dir__, '..', 'ikev2.pcapng'))[2]
              expect(gcm_pkt.to_s).to eq(expected_pkt.to_s)
            end
          end
        end
      end
    end
  end
end

