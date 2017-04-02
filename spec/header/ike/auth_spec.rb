require_relative '../../spec_helper'

module PacketGen
  module Header
    class IKE
      describe Auth do
        describe '#initialize' do
          it 'creates a Auth payload with default values' do
            auth = Auth.new
            expect(auth.next).to eq(0)
            expect(auth.flags).to eq(0)
            expect(auth.length).to eq(8)
            expect(auth.method).to eq(0)
            expect(auth.content).to be_empty
          end

          it 'accepts options' do
            opts = {
              next: 59,
              flags: 0x65,
              length: 128,
              method: 0xf0,
              content: 'abcdefghij'
            }

            auth = Auth.new(opts)
            opts.each do |k,v|
              expect(auth.send(k)).to eq(v)
            end
          end
        end

        describe '#read' do
          it 'sets Auth from a binary string' do
            str = [12, 0x80, 18, 14, 0xc0, 3, 'abcdefghij'].pack('CCnCCnA*')
            auth = Auth.new.read(str)
            expect(auth.next).to eq(12)
            expect(auth.flags).to eq(0x80)
            expect(auth.critical?).to be(true)
            expect(auth.hreserved).to eq(0)
            expect(auth.length).to eq(18)
            expect(auth.method).to eq(14)
            expect(auth.reserved).to eq(0xC00003)
            expect(auth.human_method).to eq('DIGITAL_SIGNATURE')
            expect(auth.content).to eq('abcdefghij')
          end
        end

        describe '#method=' do
          let(:auth)  { Auth.new }

          it 'accepts Integer' do
            expect { auth.method = 59 }.to_not raise_error
            expect(auth.method).to eq(59)
            expect(auth.human_method).to eq('method 59')
          end

          it 'accepts String' do
            expect { auth.method = 'ECDSA384' }.to_not raise_error
            expect(auth.method).to eq(Auth::METHOD_ECDSA384)
            expect(auth.human_method).to eq('ECDSA384')
          end

          it 'raises on unknown method (String only)' do
            expect { auth.method = 'READ_ERROR' }.to raise_error(ArgumentError)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            auth = Auth.new(next: 2, method: 'PASSWORD', content: 'abcd')
            auth.calc_length
            expected = "\x02\x00\x00\x0c\x0c\x00\x00\x00abcd"
            expect(auth.to_s).to eq(PacketGen.force_binary expected)
          end
        end

        describe '#inspect' do
          it 'returns a string with all attributes' do
            auth = Auth.new
            str = auth.inspect
            expect(str).to be_a(String)
            %i(next flags length method reserved content).each do |attr|
               expect(str).to include(attr.to_s)
             end
          end
        end

        context 'crypto' do
          before(:each) do
            @sk_pi = ['9C4E0C0F5A30F1277EEBA001356A95DB' \
                     'E6052AAE13FF634950E19C1A35F61F39'].pack('H*')
            pkts = PacketGen.read(File.join(__dir__, '..', 'ikev2.pcapng'))
            @init_pkt = pkts[0]
            @nonce_r = pkts[1].nonce.content
            @prf = pkts[1].sa.proposals.first.transforms.
                   find { |t| t.type == Transform::TYPE_PRF }.id
            @auth_pkt = pkts[2]
            sk_ei = ['B37E73D129FFE681D2E3AA3728C2401E' \
                     'D50160E39FD55EF1A1EAE0D3F4AA6126D8B8A626'].pack('H*')
            cipher = get_cipher('gcm', :decrypt, sk_ei[0..31])
            @auth_pkt.sk.decrypt! cipher, salt: sk_ei[32..35], icv_length: 16
          end

          describe '#check?' do
            it 'returns true when authentication is verified' do
              p @auth_pkt
              p @auth_pkt.headers.map(&:class)
              p @auth_pkt.auth
              p @auth_pkt.headers[10]
              result = @auth_pkt.auth.check?(init_msg: @init_pkt, nonce: @nonce_r,
                                             sk_p: @sk_pi, prf: @prf)
              expect(result).to be(true)
            end

            it 'returns false when authentication failed (bad nonceR)' do
              result = @auth_pkt.auth.check?(init_msg: @init_pkt,
                                             nonce: "\x00" * 8, sk_p: @sk_pi, prf: @prf)
              expect(result).to be(false)
            end

            it 'returns false when authentication failed (truncated init message)' do
              @init_pkt.notify(1).message_type = 43
              result = @auth_pkt.auth.check?(init_msg: @init_pkt, nonce: @nonce_r,
                                             sk_p: @sk_pi, prf: @prf)
              expect(result).to be(false)
            end

            it 'returns false when authentication failed (bad IDi)' do
              @auth_pkt.idi.type = 'IPV4_ADDR'
              @auth_pkt.idi.content = @auth_pkt.ip[:src].to_s
              result = @auth_pkt.auth.check?(init_msg: @init_pkt, nonce: @nonce_r,
                                             sk_p: @sk_pi, prf: @prf)
              expect(result).to be(false)
            end

            it 'raises unless init_msg is a Packet' do
              expect { @auth_pkt.auth.check?(init_msg: @init_pkt.ike.to_s) }.
                to raise_error(TypeError)
            end
          end
        end
      end
    end
  end
end
