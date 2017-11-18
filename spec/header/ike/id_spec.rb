require_relative '../../spec_helper'

module PacketGen
  module Header
    class IKE
      describe IDi do
        describe '#initialize' do
          it 'creates a IDi payload with default values' do
            id = IDi.new
            expect(id.next).to eq(0)
            expect(id.flags).to eq(0)
            expect(id.length).to eq(8)
            expect(id.type).to eq(1)
            expect(id.reserved).to eq(0)
            expect(id.content).to be_empty
          end

          it 'accepts options' do
            opts = {
              next: 59,
              flags: 0x65,
              length: 128,
              type: 0xf0,
              reserved: 0x123456,
              content: 'abcdefghij'
            }

            id = IDi.new(opts)
            opts.each do |k,v|
              expect(id.send(k)).to eq(v)
            end
          end
        end

        describe '#read' do
          it 'sets IDi from a binary string' do
            str = [12, 0x80, 12, 1, 0x80, 1, IPAddr.new('192.168.1.2').hton].
                  pack('CCnCCnA*')
            id = IDi.new.read(str)
            expect(id.next).to eq(12)
            expect(id.flags).to eq(0x80)
            expect(id.critical?).to be(true)
            expect(id.hreserved).to eq(0)
            expect(id.length).to eq(12)
            expect(id.type).to eq(1)
            expect(id.human_type).to eq('IPV4_ADDR')
            expect(id.reserved).to eq(0x800001)
            expect(id.human_content).to eq('192.168.1.2')

            str = [12, 0x80, 47, 10, 0, 0,
                   OpenSSL::X509::Name.parse('/CN=toto/DC=tata').to_der].pack('CCnCCnA*')
            id = IDi.new.read(str)
            expect(id.human_type).to eq('DER_ASN1_GN')
            expect(id.human_content).to eq('/CN=toto/DC=tata')
          end
        end

        describe '#type=' do
          let(:id)  { IDi.new }

          it 'accepts Integer' do
            expect { id.type = 10 }.to_not raise_error
            expect(id.type).to eq(10)
            expect(id.human_type).to eq('DER_ASN1_GN')
          end

          it 'accepts String' do
            expect { id.type = 'KEY_ID' }.to_not raise_error
            expect(id.type).to eq(IDi::TYPES['KEY_ID'])
            expect(id.human_type).to eq('KEY_ID')
          end

          it 'raises on unknown type (String only)' do
            expect { id.type = 'READ_ERROR' }.to raise_error(ArgumentError)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            id = IDi.new(next: 2, type: 'IPV6_ADDR', content: IPAddr.new('8000::1').hton)
            id.calc_length
            expected = "\x02\x00\x00\x18\x05\x00\x00\x00\x80" + "\0" * 14 + "\x01"
            expect(id.to_s).to eq(PacketGen.force_binary expected)

            name = OpenSSL::X509::Name.parse('/CN=toto/DC=tata').to_der
            id = IDi.new(next: 2, type: 'DER_ASN1_DN', content: name)
            id.calc_length
            expected = "\x02\x00\x00\x2f\x09\x00\x00\x00" + name
            expect(id.to_s).to eq(PacketGen.force_binary expected)
          end
        end

        describe '#inspect' do
          it 'returns a string with all attributes' do
            id = IDi.new
            str = id.inspect
            expect(str).to be_a(String)
            %i(next flags length type reserved content).each do |attr|
               expect(str).to include(attr.to_s)
             end
          end
        end
      end
    end
  end
end
