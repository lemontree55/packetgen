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
        it 'creates a ESP header with default values'
        it 'accepts options'
      end

      describe '#read' do
        it 'sets header from a string'
        it 'raises when str is too short'
      end

      describe 'setters' do
        it '#spi= accepts integers'
        it '#sn= accepts integers'
        it '#pad_length= accepts integers'
        it '#next= accepts integers'
      end

      describe '#to_s' do
        it 'returns a binary string'
      end
      
      describe '#inspect' do
        it 'returns a String with all attributes'
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
