require_relative '../spec_helper'

module PacketGen
  module Header
    module HTTP
      describe Response do
        describe 'binding' do
          it 'in TCP packets' do
            expect(TCP).to know_header(HTTP::Response)
          end
        end

        describe '#initialize' do
          it 'creates a HTTP Response header with default values' do
            http_resp = Response.new
            expect(http_resp).to be_a(Response)
          end
          it 'creates a HTTP Response header with given options' do
            http_resp = Response.new(status_code: "200", status_mesg: "OK")
            expect(http_resp.status_code).to eq("200")
            expect(http_resp.status_mesg).to eq("OK")
            expect(http_resp).to be_a(Response)
          end
        end

        describe 'setters' do
          let(:http_resp) { Response.new }
          it '#version= accepts strings' do
            http_resp.version = "HTTP/1.1"
            expect(http_resp.version).to eq("HTTP/1.1")
          end
          it '#status_code= accepts strings' do
            http_resp.status_code = "200"
            expect(http_resp.status_code).to eq("200")
          end
          it '#status_mesg= accepts strings' do
            http_resp.status_mesg = "OK"
            expect(http_resp.status_mesg).to eq("OK")
          end
          it '#body= accepts strings' do
            http_resp.body = "this is a body"
            expect(http_resp.body).to eq("this is a body")
          end
        end

        describe '#to_s' do
          let(:http_resp) { Response.new }
          it 'errors out without needed fields' do
            expect{ http_resp.to_s }.to raise_error(FormatError)
            http_resp.version = "HTTP/1.1"
            expect{ http_resp.to_s }.to raise_error(FormatError)
            http_resp.status_code = "200"
            expect{ http_resp.to_s }.to raise_error(FormatError)
            http_resp.status_mesg = "OK"
            expect(http_resp.to_s).to be_a(String) 
            expect(http_resp.to_s).to eq("HTTP/1.1 200 OK\r\n")
          end
          it 'returns a string with the needed fields' do 
            http_resp.version = "HTTP/1.1"
            http_resp.status_code = "200"
            http_resp.status_mesg = "OK"
            expect(http_resp.to_s).to be_a(String) 
            expect(http_resp.to_s).to eq("HTTP/1.1 200 OK\r\n")
          end
        end

        describe '#read' do
          let(:http_resp) { Response.new }
          it 'parses http response data from a string' do
            http_resp.read("HTTP/1.1 200 OK\r\nHost: tcpdump.org\r\ndogs: lol\r\n\r\n")	
            expect(http_resp.version).to eq("HTTP/1.1")
            expect(http_resp.status_code).to eq("200")
            expect(http_resp.status_mesg).to eq("OK")
            expect(http_resp.headers).to eq({"Host"=>"tcpdump.org", "dogs"=>"lol"})
          end
        end

        describe '#inspect' do
          let(:http_resp) { Response.new }
          it 'returns a String with all attributes' do
            expect(http_resp.inspect).to be_a(String)
          end
        end
      end
    end
  end
end
