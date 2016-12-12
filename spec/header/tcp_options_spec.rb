require_relative '../spec_helper'

module PacketGen
  module Header
    class TCP

      SINGLES = [[EOL, "\x00"], [NOP, "\x01"], [MSS, "\x02\x04\x12\x23"],
                 [WS, "\x03\x03\xff"], [SACKOK, "\x04\x02"],
                 [SACK, "\x05\x05\x01\x02\x03"],
                 [SACK, "\x05\x12"+(16..31).to_a.pack('C*')],
                 [ECHO, "\x06\x06\x04\x03\x02\x01"],
                 [ECHOREPLY, "\x07\x06\x04\x03\x02\x01"],
                 [TS, "\x08\x0a" + "\x00" * 8]
                ]

      describe Options do
        before(:all) do
          file = File.join(__dir__, '..', 'pcapng', 'ipv6_tcp.pcapng')
          @packets = PcapNG::File.new.read_packet_bytes(file)
          end

        let(:opts) { Options.new }

        describe '#read' do
          it 'reads a single option from a string' do
            SINGLES.each do |klass, str|
              opts.read str
              expect(opts.size).to eq(1)
              expect(opts.first).to be_a(klass)
              case opts.first
              when MSS
                expect(opts.first.value).to eq(0x1223)
              when WS
                expect(opts.first.value).to eq(0xff)
              when SACKOK
                expect(opts.first.value).to eq('')
              when SACK
                sack = opts.first
                case sack.length
                when 5; expect(sack.value).to eq("\x01\x02\x03")
                when 18; expect(sack.value).to eq((16..31).to_a.pack('C*'))
                end
              when ECHO, ECHOREPLY
                expect(opts.first.value).to eq(0x04030201)
              when TS
                expect(opts.first.value).to eq("\0" * 8)
              end               
            end
          end

          it 'reads multiple options from a string' do
            str = @packets.first[0x4a..-1]
            opts.read str
            expect(opts.size).to eq(5)
            expect(opts[0]).to be_a(MSS)
            expect(opts[0].value).to eq(0x58c)
            expect(opts[1]).to be_a(SACKOK)
            expect(opts[2]).to be_a(TS)
            expect(opts[2].value).to eq([0x02343d6d, 0].pack('N2'))
            expect(opts[3]).to be_a(NOP)
            expect(opts[4]).to be_a(WS)
            expect(opts[4].value).to eq(7)

            str = @packets[2][0x4a..-1]
            opts.read str
            expect(opts.size).to eq(3)
            expect(opts.map { |o| o.class }).to eq([NOP, NOP, TS])
          end
        end

        describe '#to_s' do
          it 'returns encoded options' do
            @packets.each do |pkt|
              str_opts = pkt[0x4a..-1]
              opts.read str_opts
              expect(opts.to_s).to eq(str_opts)
            end
          end
        end
      end
    end
  end
end
