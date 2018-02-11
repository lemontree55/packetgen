require_relative '../../spec_helper'

module PacketGen
  module Header
    class IKE
      describe Attribute do
        describe '#initialize' do
          it 'creates a Attribute with default values' do
            attr = Attribute.new
            expect(attr.type).to eq(0)
            expect(attr.length).to eq(8)
            expect(attr.value).to eq(0)
            expect(attr.tv_format?).to be(false)
          end

          it 'accepts options in TLV format' do
            options = {
              type: 0x7fff,
              length: 12,
              value: 0x01020304
            }
            attr = Attribute.new(options)
            expect(attr.tv_format?).to be(false)
            options.each do |key, value|
              expect(attr.send(key)).to eq(value)
            end
          end

          it 'accepts options in TV format' do
            options = {
              type: 0x8001,
              value: 0x0102
            }
            attr = Attribute.new(options)
            expect(attr.tv_format?).to be(true)
            expect(attr.length).to eq(4)
            options.each do |key, value|
              expect(attr.send(key)).to eq(value)
            end
          end
        end

        describe '#read' do
          it 'reads a TLV attribute' do
            str = [128, 8, 0x12345678].pack('nnN')
            attr = Attribute.new.read(str)
            expect(attr.tv_format?).to be(false)
            expect(attr.type).to eq(128)
            expect(attr.length).to eq(8)
            expect(attr.value).to eq(0x12345678)
          end

          it 'reads a TV attribute' do
            str = [0x8001, 0x1234].pack('nn')
            attr = Attribute.new.read(str)
            expect(attr.tv_format?).to be(true)
            expect(attr.type).to eq(0x8001)
            expect(attr.length).to eq(4)
            expect(attr.value).to eq(0x1234)
          end
        end

        describe '#to_s' do
          it 'returns a binary string for TLV Attribute' do
            attr = Attribute.new(type: 12, value: 0x01234567)
            expected = [12, 8, 0x01234567].pack('nnN')
            expect(attr.to_s).to eq(force_binary expected)
          end

          it 'returns a binary string for TV Attribute' do
            attr = Attribute.new(type: 0x8012, value: 0x01234567)
            expected = [0x8012, 0x4567].pack('nn')
            expect(attr.to_s).to eq(force_binary expected)
          end

        end

        describe '#to_human' do
          it 'returns a human readbale string for TLV Attribute' do
            attr = Attribute.new(type: 12, value: 0x01234567)
            expect(attr.to_human).to eq('attr[12]=19088743')
          end

          it 'returns a human readbale string for TV Attribute' do
            attr = Attribute.new(type: 0x800e, value: 256)
            expect(attr.to_human).to eq('KEY_LENGTH=256')
            attr = Attribute.new(type: 0x800f, value: 256)
            expect(attr.to_human).to eq('attr[15]=256')
          end
        end
      end

      describe Transform do
        before(:each) do
          @str = "\x03\x00\x00\f\x01\x00\x00\x14\x80\x0E\x01\x00"
          @trans = Transform.new.read(@str)
        end

        describe '#initialize' do
          it 'creates a Transform with default values' do
            trans = Transform.new
            expect(trans.last).to eq(0)
            expect(trans.last?).to be(true)
            expect(trans.rsv1).to eq(0)
            expect(trans.length).to eq(8)
            expect(trans.type).to eq(1)
            expect(trans.rsv2).to eq(0)
            expect(trans.id).to eq(0)
            expect(trans.attributes).to be_empty
          end

          it 'accepts options' do
            options = {
              last: 0xff,
              rsv1: 12,
              length: 0x123,
              type: 1,
              rsv2: 24,
              id: 0x0102
            }
            trans = Transform.new(options)
            options.each do |key, value|
              expect(trans.send(key)).to eq(value)
            end
          end

          it 'accepts String for type and id options' do
            trans = Transform.new(type: 'DH', id: 'ECP384')
            expect(trans.type).to eq(Transform::TYPES['DH'])
            expect(trans.id).to eq(Transform::DH_ECP384)
          end

          it 'raises on unknwon string type' do
            expect { Transform.new(type: 'UNKNOWN') }.to raise_error(ArgumentError)
          end

          it 'raises on unknwon string ID' do
            expect { Transform.new(id: 'UNKNOWN') }.to raise_error(ArgumentError)
          end
        end

        describe '#read' do
          it 'sets transform from a binary string' do
            expect(@trans.last).to eq(3)
            expect(@trans.last?).to be(false)
            expect(@trans.rsv1).to eq(0)
            expect(@trans.length).to eq(12)
            expect(@trans.type).to eq(1)
            expect(@trans.human_type).to eq('ENCR')
            expect(@trans.rsv2).to eq(0)
            expect(@trans.id).to eq(20)
            expect(@trans.human_id).to eq('AES_GCM16')
            expect(@trans.attributes.size).to eq(1)
            expect(@trans.attributes.first.to_human).to eq('KEY_LENGTH=256')
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            expect(@trans.to_s).to eq(@str)
          end
        end

        describe '#to_human' do
          it 'returns a human readable string with defined type and ID' do
            expect(@trans.to_human).to eq('ENCR(AES_GCM16,KEY_LENGTH=256)')
          end

          it 'returns a human readable string with undefined type and ID' do
            @trans[:type].read 50
            @trans.id = 60
            @trans.attributes.clear
            expect(@trans.to_human).to eq('type[50](ID=60)')
          end

          describe '#attributes' do
            let (:trans) { Transform.new }

            it 'accepts an Attribute' do
              attr = Attribute.new(type: 0x800e, value: 128)
              expect { trans.attributes << attr }.to change(trans.attributes, :size).by(1)
              attr = Attribute.new(type: 12, value: 7)
              expect { trans.attributes << attr }.to change(trans.attributes, :size).by(1)
              expect(trans.to_human).to eq('ENCR(ID=0,KEY_LENGTH=128,attr[12]=7)')
            end

            it 'accepts a Hash describing an attribute' do
              expect { trans.attributes << { type: 0x800e, value: 192 } }.
                to change(trans.attributes, :size).by(1)
              expect(trans.attributes.first).to be_a(Attribute)
              expect(trans.to_human).to eq('ENCR(ID=0,KEY_LENGTH=192)')
            end
          end
        end
      end

      describe SAProposal do
        before(:each) do
          @str = [2, 0, 28, 1, 3, 4, 2, 0x12345678,
                  3, 0, 8, 1, 0, 1,
                  0, 0, 8, 3, 0, 10].pack('CCnCCCCNCCnCCnCCnCCn')
          @prop = SAProposal.new.read(@str)
        end

        describe '#initialize' do
          it 'creates a SAProposal with default values' do
            prop = SAProposal.new
            expect(prop.last).to eq(0)
            expect(prop.last?).to be(true)
            expect(prop.reserved).to eq(0)
            expect(prop.length).to eq(8)
            expect(prop.num).to eq(1)
            expect(prop.protocol).to eq(0)
            expect(prop.spi_size).to eq(0)
            expect(prop.num_trans).to eq(0)
            expect(prop.spi).to be_empty
            expect(prop.transforms).to be_empty
          end

          it 'accepts options' do
            opts = {
              last: 43,
              reserved: 55,
              length: 1200,
              num: 6,
              protocol: 155,
              spi_size: 12,
              num_trans: 28
            }
            prop = SAProposal.new(opts)
            expect(prop.last?).to be(nil)
            opts.each do |k,v|
              expect(prop.send(k)).to eq(v)
            end
          end

          it 'accepts String for protocol option' do
            prop = SAProposal.new(protocol: 'IKE')
            expect(prop.protocol).to eq(1)
          end

          it 'raises on unknwon string type' do
            expect { SAProposal.new(protocol: 'TCP') }.to raise_error(ArgumentError)
          end
        end

        describe '#read' do
          it 'sets proposal from a binary string' do
            expect(@prop.last?).to be(false)
            expect(@prop.reserved).to eq(0)
            expect(@prop.length).to eq(28)
            expect(@prop.num).to eq(1)
            expect(@prop.human_protocol).to eq('ESP')
            expect(@prop.spi_size).to eq(4)
            expect(@prop.num_trans).to eq(2)
            expect(Types::Int32.new.read(@prop.spi).to_i).to eq(0x12345678)
            expect(@prop.transforms.size).to eq(2)
            expect(@prop.transforms.to_human).to eq('ENCR(DES_IV64),INTG(AES192_GMAC)')
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            expect(@prop.to_s).to eq(@str)
          end
        end

        describe '#to_human' do
          it 'returns a human readable string' do
            expect(@prop.to_human).to eq('#1 ESP(spi:0x12345678):ENCR(DES_IV64),INTG(AES192_GMAC)')

            prop = SAProposal.new(num: 2, protocol: 'IKE', spi: [0x123456789].pack('Q>'))
            prop.transforms << { type: 'INTG', id: 'HMAC_MD5_96' }
            expect(prop.to_human).to eq('#2 IKE(spi:0x0000000123456789):INTG(HMAC_MD5_96)')
          end
        end

        describe '#transforms' do
          it 'accepts pushing a Tranform object' do
            expect(@prop.transforms[1].last?).to be(true)
            trans = Transform.new(type: 5, id: 0)
            expect { @prop.transforms << trans }.to change { @prop.num_trans }.by(1)
            expect(@prop.transforms[1].last?).to be(false)
            expect(@prop.transforms[2].last?).to be(true)
          end

          it 'accepts pushing a Hash describing a tranform' do
            trans = { type: 5, id: 0 }
            expect { @prop.transforms << trans }.to change { @prop.num_trans }.by(1)
            expect(@prop.transforms.size).to eq(3)
            expect(@prop.transforms[1].last?).to be(false)
            expect(@prop.transforms[2].last?).to be(true)
          end
        end
      end

      describe SA do
        before(:all) do
          @str = ['220000300000002c010100040300000c01000014800e0100030000080300000c' \
                  '03000008020000050000000804000013'].pack('H*')
        end
        before(:each) do
          @sa = SA.new.read(@str)
        end

        describe '#initialize' do
          it 'creates a SA payload with default values' do
            sa = SA.new
            expect(sa.next).to eq(0)
            expect(sa.flags).to eq(0)
            expect(sa.length).to eq(4)
            expect(sa.proposals).to be_empty
          end

          it 'accepts options' do
            opts = {
              next: 59,
              flags: 0x65,
              length: 128
            }

            sa = SA.new(opts)
            opts.each do |k,v|
              expect(sa.send(k)).to eq(v)
            end
          end
        end

        describe '#read' do
          it 'sets SA from a binary string' do
            expect(@sa.next).to eq(0x22)
            expect(@sa.flags).to eq(0)
            expect(@sa.length).to eq(0x0030)
            expect(@sa.proposals.size).to eq(1)
            proposal = @sa.proposals.first
            expect(proposal.last?).to be(true)
            expect(proposal.length).to eq(44)
            expect(proposal.num).to eq(1)
            expect(proposal.human_protocol).to eq('IKE')
            expect(proposal.spi_size).to eq(0)
            expect(proposal.spi).to be_empty
            expect(proposal.num_trans).to eq(4)
            expect(proposal.transforms.size).to eq(4)
            expect(proposal.transforms.map(&:human_type)).to eq(%w(ENCR INTG PRF DH))
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            expect(@sa.to_s).to eq(@str)
          end
        end

        describe '#inspect' do
          it 'returns a string with all attributes' do
            str = @sa.inspect
            expect(str).to be_a(String)
            (@sa.fields - %i(body)).each do |attr|
               expect(str).to include(attr.to_s)
             end
          end
        end

        describe '#proposals' do
          it 'accepts pushing a SAProposal object' do
            prop = SAProposal.new(num: 2, protocol: 'AH', spi: [0x12345678].pack('N'))
            expect { @sa.proposals << prop }.to change { @sa.proposals.size }.by(1)
            expected = '#1 IKE:ENCR(AES_GCM16,KEY_LENGTH=256),INTG(HMAC_SHA2_256_128),' \
                       'PRF(HMAC_SHA2_256),DH(ECP256); #2 AH(spi:0x12345678):'
            expect(@sa.proposals.to_human).to eq(expected)
            expect(@sa.proposals.first.last?).to be(false)
            expect(@sa.proposals.last.last?).to be(true)
          end

          it 'accepts pushing a Hash describing a proposal' do
            expect { @sa.proposals << { num: 2, protocol: 'IKE', last: 43 } }.
              to change { @sa.proposals.size }.by(1)
            expected = '#1 IKE:ENCR(AES_GCM16,KEY_LENGTH=256),INTG(HMAC_SHA2_256_128),' \
                       'PRF(HMAC_SHA2_256),DH(ECP256); #2 IKE:'
            expect(@sa.proposals.to_human).to eq(expected)
            expect(@sa.proposals.first.last?).to be(false)
            expect(@sa.proposals.last.last?).to be(true)
          end
        end

        describe '#calc_length' do
          it 'sets real length to length field' do
            @sa.proposals << { num: 2, protocol: 'IKE', last: 43 }
            expect { @sa.calc_length }.to change { @sa.length }.from(48).to(56)
          end

          it 'sets length fields recursively' do
            @sa.proposals << { num: 2, protocol: 'IKE', last: 43 }
            @sa.proposals.last.transforms << { type: 'ENCR', id: 'AES_CTR' }
            @sa.proposals.last.transforms.last.attributes << { type: 0x800e, value: 128 }
            expect(@sa.proposals.last.length).to eq(8)
            expect(@sa.proposals.last.transforms.last.length).to eq(8)
            @sa.calc_length
            expect(@sa.proposals.last.length).to eq(20)
            expect(@sa.proposals.last.transforms.last.length).to eq(12)
          end
        end
      end
    end
  end
end
