require_relative '../../spec_helper'

module PacketGen
  module Header
    class DNS

      describe QDSection do

        before(:each) do
          @dns = DNS.new
          @counter = StructFu::Int32.new(0)
          @section = QDSection.new(@dns, @counter)
        end

        describe '#read' do
          it 'reads a binary string' do
            q1 = Question.new(@dns, name: 'example.org')
            q2 = Question.new(@dns, name: 'example.com.')
            str = q1.to_s << q2.to_s
            @section.read str
            expect(@section.size).to eq(0)

            @counter.read 2
            @section.read str
            expect(@section.size).to eq(2)
            expect(@section.all? { |q| q.is_a? Question }).to be(true)
            expect(@section[0].to_s).to eq(q1.to_s)
            expect(@section[1].to_s).to eq(q2.to_s)
          end
        end
      end
    end
  end
end
