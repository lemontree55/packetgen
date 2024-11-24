# frozen_string_literal: true

require_relative '../../spec_helper'

module PacketGen
  module Header
    module HTTP
      describe Headers do
        let(:headers) { Headers.new }
        let(:hsh) { { 'Content-Type' => 'text/html', 'Connection' => 'keep-alive' } }
        let(:encoded_headers) { "Content-Type: text/html\r\nConnection: keep-alive\r\n\r\n" }

        it 'is BinStruct::Structable' do
          expect(Headers < BinStruct::Structable).to be(true)
        end

        describe '#read' do
          it 'reads headers from a string' do
            headers.read(encoded_headers)
            expect(headers.data.size).to eq(2)
            expect(headers.data).to eq(hsh)
            expect(headers).to have_header('Content-Type')
            expect(headers['Content-Type']).to eq('text/html')
            expect(headers).to have_header('Connection')
            expect(headers['Connection']).to eq('keep-alive')
          end

          it 'reads from a Hash' do
            headers.read(hsh)
            expect(headers.data).to eq(hsh)
          end
        end

        describe '#to_s' do
          it 'returns void headers' do
            expect(headers.to_s).to eq("\r\n")
          end

          it 'returns encoded headers' do
            headers.read(hsh)
            expect(headers.to_s).to eq(encoded_headers)
          end
        end
      end
    end
  end
end
