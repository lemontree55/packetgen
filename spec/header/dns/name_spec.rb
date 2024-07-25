require_relative '../../spec_helper'

module PacketGen
  module Header
    class DNS

      describe Name do
        let(:name) { Name.new }
        let(:dns) { DNS.new }

        describe '#initialize' do
          it 'creates a Name with default values' do
            expect(name.to_human).to eq('.')
          end
        end

        describe '#read' do
          it 'sets Name from a binary string' do
            name.read(binary "\0")
            expect(name.to_human).to eq('.')

            name.read generate_label_str(['www', 'example', 'net'])
            expect(name.to_human).to eq('www.example.net.')
          end

          it 'may decode a name pointer' do
            dns.qd << Question.new(dns, name: 'example.net')
            name.dns = dns

            offset = DNS.new.sz
            str = binary("\x03www" + [0xc0, offset].pack('C2'))
            name.read(str)
            expect(name.to_human).to eq('www.example.net.')
          end
        end
      end
    end
  end
end
