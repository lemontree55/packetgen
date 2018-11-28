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
          it 'creates a TCP header with default values' do
            http_req = Request.new
            expect(http_req).to be_a(Request)
          end
          it 'creates a TCP header with given options' do
            http_req = Request.new(verb: "GET", path: "/", headers: {'User-Agent' => 'dummy/1.0' })
            expect(http_req).to be_a(Request)
            expect(http_req.verb).to eq("GET")
            expect(http_req.path).to eq("/")
            expect(http_req.headers).to eq({'User-Agent' => 'dummy/1.0' })
          end
        end

        describe 'setters' do
          let(:http_req) { Request.new }
          it '#verb= accepts strings' do
            http_req.verb = "GET"
            expect(http_req.verb).to eq("GET")
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
            http_req.verb = "GET"
            expect{ http_req.to_s }.to raise_error(FormatError)
            http_req.path = "/"
            expect(http_req.to_s).to be_a(String)
          end
          it 'returns a string with the needed fields' do
            http_req.verb = "GET"
            http_req.path = "/"
            expect(http_req.to_s).to be_a(String)
          end
        end

        describe '#read' do
          let(:http_req) { Request.new }
          it 'parses http request data from a string' do
            http_req.read("GET / HTTP/1.1\r\nUser-Agent: dummy/1.0\r\n\r\n")
            expect(http_req.verb).to eq("GET")
            expect(http_req.path).to eq("/")
            expect(http_req.version).to eq("HTTP/1.1")
            expect(http_req.headers).to eq({"User-Agent" => "dummy/1.0"})
          end
          it 'parses weird http request data from a string with invalid encoding' do
            http_req.read("GET / HTTP/1.1\r\nUser-Agent: dummy/1.0\r\n\r\n\r\xD1")
            expect(http_req.verb).to eq("GET")
            expect(http_req.path).to eq("/")
            expect(http_req.version).to eq("HTTP/1.1")
            expect(http_req.headers).to eq({"User-Agent" => "dummy/1.0"})
            expect(http_req.body.bytes).to eq("\r\xD1".bytes)
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
