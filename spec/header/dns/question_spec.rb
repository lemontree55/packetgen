require_relative '../../spec_helper'

module PacketGen
  module Header
    class DNS

      describe Question do
        let(:dns) { DNS.new }

        describe '#initialize' do
          it 'creates a Question with default values' do
            q = Question.new(dns)
            expect(q.name.to_s).to eq('')
            expect(q.type).to eq(1)
            expect(q.rrclass).to eq(1)
          end

          it 'accepts options' do
            options = {
              name: 'www.example.net.',
              type: 253,
              rrclass: 65000
            }
            q = Question.new(dns, options)

            expect(q.name.to_human).to eq(options.delete :name)
            options.each do |key, value|
              expect(q.send(key)).to eq(value)
            end
          end
        end

        describe '#read' do
          it 'sets question from a string' do
            str = [0, 2, 3].pack('Cnn')
            q = Question.new(dns).read(str)
            expect(q.name.to_human).to eq('.')
            expect(q.type).to eq(2)
            expect(q.rrclass).to eq(3)

            str = [7, 'example', 3, 'org', 0, 1, 1].pack('CA7CA3Cnn')
            q = Question.new(dns).read(str)
            expect(q.name.to_human).to eq('example.org.')
            expect(q.type).to eq(1)
            expect(q.rrclass).to eq(1)
          end
        end

        describe 'setters' do
          let(:q) { Question.new(dns) }

          it '#type= accepts an Integer' do
            q.type = 0xacac
            expect(q[:type].to_i).to eq(0xacac)
          end

          it '#type= accepts a String' do
            Question::TYPES.each do |key, value|
              q.type = key
              expect(q[:type].to_i).to eq(value)
            end
          end

          it '#type= raises an error when string is unknown' do
            expect { q.type = 'blah' }.to raise_error(ArgumentError, /unknown type/)
          end

          it '#rrclass= accepts an Integer' do
            q.rrclass = 0xacac
            expect(q[:rrclass].to_i).to eq(0xacac)
          end

          it '#rrclass= accepts a String' do
            Question::CLASSES.each do |key, value|
              q.rrclass = key
              expect(q[:rrclass].to_i).to eq(value)
            end
          end

          it '#rrclass= raises an error when string is unknown' do
            expect { q.rrclass = 'blah' }.to raise_error(ArgumentError, /unknown class/)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            q = Question.new(dns, name: 'example.net')
            expected_str = [7, 'example', 3, 'net', 0, 1, 1].pack('CA7CA3Cnn')
            expect(q.to_s).to eq(PacketGen.force_binary expected_str)
          end
        end

        describe '#to_human' do
          it 'returns a human readable string' do
            q = Question.new(dns, name: 'example.net')
            expect(q.to_human).to eq('A IN example.net.')
            q = Question.new(dns, name: 'example.net', type: 12, rrclass: 3)
            expect(q.to_human).to eq('PTR CH example.net.')
          end
        end
      end
    end
  end
end
