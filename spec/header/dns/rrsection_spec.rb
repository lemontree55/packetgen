require_relative '../../spec_helper'

module PacketGen
  module Header
    class DNS

      describe RRSection do

        before(:each) do
          @dns = DNS.new
          @counter = StructFu::Int32.new(0)
          @section = RRSection.new(@dns, @counter)
        end

        describe '#push' do
          it 'adds an object to section' do
            obj = Object.new
            @section.push obj
            expect(@section).to include(obj)
          end

          it 'supports special hash with rtype key' do
            name = 'example.net'
            ipaddr = '1.2.3.4'
            @section.push(rtype: 'Question', name: name)
            @section.push(rtype: 'RR', name: name, rdata: IPAddr.new(ipaddr).hton)

            expect(@section[0]).to be_a(Question)
            expect(@section[0].to_human).to eq("A IN #{name}.")
            expect(@section[1]).to be_a(RR)
            expect(@section[1].to_human).to eq("A IN #{name}. TTL 0 #{ipaddr}")
          end

          it 'does not increment counter associated to section' do
            obj = Object.new
            expect { @section.push obj }.to_not change { @counter.value }
          end
        end

        describe '#<<' do
          it 'adds an object to section' do
            obj = Object.new
            @section << obj
            expect(@section).to include(obj)
          end

          it 'supports special hash with rtype key' do
            name = 'example.net'
            ipaddr = '1.2.3.4'
            @section << { rtype: 'Question', name: name }
            @section << { rtype: 'RR', name: name, rdata: IPAddr.new(ipaddr).hton }
            @section << { rtype: 'OPT', udp_size: 4096 }

            expect(@section[0]).to be_a(Question)
            expect(@section[0].to_human).to eq("A IN #{name}.")
            expect(@section[1]).to be_a(RR)
            expect(@section[1].to_human).to eq("A IN #{name}. TTL 0 #{ipaddr}")
            expect(@section[2]).to be_a(OPT)
            expect(@section[2].to_human).to eq('. OPT UDPsize:4096 extRCODE:0 ' \
                                               'EDNSversion:0 flags:none options:none')
          end

          it 'increments counter associated to section' do
            obj = Object.new
            expect { @section << obj }.to change { @counter.value }.by(1)
          end
        end

        describe '#delete' do
          it 'removes and returns an object from section' do
            obj = Object.new
            @section << obj
            expect(@section).to include(obj)
            deleted = @section.delete obj
            expect(@section).to_not include(obj)
            expect(deleted).to eql(obj)
          end

          it 'decrements counter associated to section' do
            obj = Object.new
            @section << obj
            expect { @section.delete obj }.to change { @counter.value }.by(-1)
          end
        end

        describe '#read' do
          it 'reads a binary string' do
            rr1 = RR.new(@dns, name: 'example.org.', type: 'CNAME', rdata: 'example.com.')
            rr2 = RR.new(@dns, name: 'example.org.', rdata: IPAddr.new('10.0.0.1').hton)
            str = rr1.to_s << rr2.to_s
            @section.read str
            expect(@section.size).to eq(0)

            @counter.read 2
            @section.read str
            expect(@section.size).to eq(2)
            expect(@section.all? { |rr| rr.is_a? RR }).to be(true)
            expect(@section[0].to_s).to eq(rr1.to_s)
            expect(@section[1].to_s).to eq(rr2.to_s)
          end
        end
      end
    end
  end
end
