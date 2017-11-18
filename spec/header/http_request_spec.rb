require_relative '../spec_helper'

module PacketGen
  module Header
    module HTTP
      describe Request do
        describe 'binding' do
          it 'in TCP packets' do
            expect(TCP).to know_header(HTTP::Request)
          end
        end

        describe '#initialize' do
          let(:http_req) { Request.new }
          it 'creates a TCP header with default values' do
            expect(http_req).to be_a(Request)
          end
        end

        describe 'setters' do
          let(:http_req) { Request.new }
          it '#method= accepts strings' do
            http_req.method = "GET"
            expect(http_req.method).to eq("GET")
          end
          it '#path= accepts strings' do
            http_req.path = "/"
            expect(http_req.path).to eq("/")
          end
          it '#version= accepts strings' do
            http_req.version = "HTTP/1.1"
            expect(http_req.version).to eq("HTTP/1.1")
          end
        end

        describe '#to_s' do
          let(:http_req) { Request.new }
          it 'errors out without needed fields' do
            expect{ http_req.to_s }.to raise_error(FormatError)
            http_req.method = "GET"
            expect{ http_req.to_s }.to raise_error(FormatError)
            http_req.path = "/"
            expect(http_req.to_s).to be_a(String) 
          end
          it 'returns a string with the needed fields' do 
            http_req.method = "GET"
            http_req.path = "/"
            expect(http_req.to_s).to be_a(String) 
          end
        end

        describe '#inspect' do
          let(:http_req) { Request.new }
          it 'returns a String with all attributes' do
            expect(http_req.inspect).to be_a(String)
          end
        end
      end
    end
  end
end
