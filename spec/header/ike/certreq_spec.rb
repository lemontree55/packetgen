require_relative '../../spec_helper'

module PacketGen
  module Header
    class IKE
      describe CertReq do
        describe '#initialize' do
          it 'creates a CertReq payload with default values' do
            certreq = CertReq.new
            expect(certreq.next).to eq(0)
            expect(certreq.flags).to eq(0)
            expect(certreq.length).to eq(5)
            expect(certreq.encoding).to eq(1)
            expect(certreq.content).to be_empty
          end

          it 'accepts options' do
            opts = {
              next: 59,
              flags: 0x65,
              length: 128,
              encoding: 13,
              content: 'abcdefghij'
            }

            certreq = CertReq.new(opts)
            opts.each do |k,v|
              expect(certreq.send(k)).to eq(v)
            end
          end
        end

        describe '#read' do
          it 'sets CertReq from a binary string' do
            str = [12, 0x80, 15, 1, 'abcdefghij'].pack('CCnCA*')
            certreq = CertReq.new.read(str)
            expect(certreq.next).to eq(12)
            expect(certreq.flags).to eq(0x80)
            expect(certreq.critical?).to be(true)
            expect(certreq.hreserved).to eq(0)
            expect(certreq.length).to eq(15)
            expect(certreq.encoding).to eq(1)
            expect(certreq.human_encoding).to eq('PKCS7_WRAPPED_X509')
            expect(certreq.content).to eq('abcdefghij')
          end
        end

        describe '#encoding=' do
          let(:certreq)  { CertReq.new }

          it 'accepts Integer' do
            expect { certreq.encoding = 2 }.to_not raise_error
            expect(certreq.encoding).to eq(2)
            expect(certreq.human_encoding).to eq('PGP')
          end

          it 'accepts String' do
            expect { certreq.encoding = 'X509_CRL' }.to_not raise_error
            expect(certreq.encoding).to eq(CertReq::ENCODINGS['X509_CRL'])
            expect(certreq.human_encoding).to eq('X509_CRL')
          end

          it 'raises on unknown encoding (String only)' do
            expect { certreq.encoding = 'READ_ERROR' }.to raise_error(ArgumentError)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            certreq = CertReq.new(next: 2, encoding: 'X509_CERT_SIG', content: 'a' * 20)
            certreq.calc_length
            expected = "\x02\x00\x00\x19\x04" + 'a' * 20
            expect(certreq.to_s).to eq(force_binary expected)
          end
        end

        describe '#inspect' do
          it 'returns a string with all attributes' do
            certreq = CertReq.new(content: 'a' * 20 + 'b' * 20)
            str = certreq.inspect
            expect(str).to be_a(String)
            (certreq.fields - %i(body)).each do |attr|
              expect(str).to include(attr.to_s)
              if attr == :content
                expect(str).to match(/^\s+hashes/)
                expect(str).to include('"' + 'a' * 20 + '","'  + 'b' * 20 + '"')
              end
             end
          end
        end
      end
    end
  end
end
