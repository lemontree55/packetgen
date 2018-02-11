require_relative '../../spec_helper'

module PacketGen
  module Header
    class IKE
      describe Cert do
        describe '#initialize' do
          it 'creates a Cert payload with default values' do
            cert = Cert.new
            expect(cert.next).to eq(0)
            expect(cert.flags).to eq(0)
            expect(cert.length).to eq(5)
            expect(cert.encoding).to eq(1)
            expect(cert.content).to be_empty
          end

          it 'accepts options' do
            opts = {
              next: 59,
              flags: 0x65,
              length: 128,
              encoding: 9,
              content: 'abcdefghij'
            }

            cert = Cert.new(opts)
            opts.each do |k,v|
              expect(cert.send(k)).to eq(v)
            end
          end
        end

        describe '#read' do
          it 'sets Cert from a binary string' do
            str = [12, 0x80, 15, 1, 'abcdefghij'].pack('CCnCA*')
            cert = Cert.new.read(str)
            expect(cert.next).to eq(12)
            expect(cert.flags).to eq(0x80)
            expect(cert.critical?).to be(true)
            expect(cert.hreserved).to eq(0)
            expect(cert.length).to eq(15)
            expect(cert.encoding).to eq(1)
            expect(cert.human_encoding).to eq('PKCS7_WRAPPED_X509')
            expect(cert.content).to eq('abcdefghij')
          end
        end

        describe '#encoding=' do
          let(:cert)  { Cert.new }

          it 'accepts Integer' do
            expect { cert.encoding = 9 }.to_not raise_error
            expect(cert.encoding).to eq(9)
            expect(cert.human_encoding).to eq('SPKI_CERT')
          end

          it 'accepts String' do
            expect { cert.encoding = 'X509_CRL' }.to_not raise_error
            expect(cert.encoding).to eq(Cert::ENCODINGS['X509_CRL'])
            expect(cert.human_encoding).to eq('X509_CRL')
          end

          it 'raises on unknown encoding (String only)' do
            expect { cert.encoding = 'READ_ERROR' }.to raise_error(ArgumentError)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            cert = Cert.new(next: 2, encoding: 'X509_CERT_SIG', content: 'abcd')
            cert.calc_length
            expected = "\x02\x00\x00\x09\x04abcd"
            expect(cert.to_s).to eq(force_binary expected)
          end
        end

        describe '#inspect' do
          it 'returns a string with all attributes' do
            cert = Cert.new
            str = cert.inspect
            expect(str).to be_a(String)
            (cert.fields - %i(body)).each do |attr|
               expect(str).to include(attr.to_s)
             end
          end
        end
      end
    end
  end
end
