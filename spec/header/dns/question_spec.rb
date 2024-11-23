# frozen_string_literal: true

require_relative '../../spec_helper'

module PacketGen
  module Header
    class DNS
      describe Question do
        let(:dns) { DNS.new }

        describe '#initialize' do
          it 'creates a Question with default values' do
            q = Question.new(dns)
            expect(q.name.to_s).to eq('.')
            expect(q.type).to eq(1)
            expect(q.rrclass).to eq(1)
          end

          it 'accepts options' do
            options = {
              name: 'www.example.net.',
              type: 250,
              rrclass: 254
            }
            q = Question.new(dns, options)

            expect(q.name).to eq(options.delete(:name))
            options.each do |key, value|
              expect(q.send(key)).to eq(value)
            end
          end
        end

        describe '#read' do
          it 'sets question from a string' do
            str = [0, 2, 3].pack('Cnn')
            q = Question.new(dns).read(str)
            expect(q.name).to eq('.')
            expect(q.type).to eq(2)
            expect(q.rrclass).to eq(3)

            str = generate_label_str(%w[example org]) << [1, 1].pack('nn')
            q = Question.new(dns).read(str)
            expect(q.name).to eq('example.org.')
            expect(q.type).to eq(1)
            expect(q.rrclass).to eq(1)
          end
        end

        describe '#to_s' do
          it 'returns a binary string' do
            q = Question.new(dns, name: 'example.net')
            expected_str = generate_label_str(%w[example net]) << [1, 1].pack('nn')
            expect(q.to_s).to eq(binary(expected_str))
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
