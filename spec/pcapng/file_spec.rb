require 'tempfile'
require_relative '../spec_helper'
require_relative 'file_spec_helper'

module PacketGen
  module PcapNG
    describe File do
      before(:all) do
        @file = ::File.join(__dir__, 'sample.pcapng')
        @file_spb = ::File.join(__dir__, 'sample-spb.pcapng')
      end
      before(:each) { @pcapng = File.new }

      describe '#readfile' do
        it 'reads a Pcap-NG file' do
          @pcapng.readfile @file
          expect(@pcapng.sections.size).to eq(1)
          expect(@pcapng.sections[0].unknown_blocks.size).to eq(0)

          expect(@pcapng.sections.first.interfaces.size).to eq(1)
          intf = @pcapng.sections.first.interfaces.first
          expect(intf.section).to eq(@pcapng.sections.first)

          expect(intf.packets.size).to eq(11)
          packet = intf.packets.first
          expect(packet.interface).to eq(intf)
        end

        it 'reads a Pcap-NG file with Simple Packet blocks' do
          @pcapng.readfile @file_spb
          expect(@pcapng.sections.size).to eq(1)
          expect(@pcapng.sections[0].unknown_blocks.size).to eq(0)
          expect(@pcapng.sections.first.interfaces.size).to eq(1)
          intf = @pcapng.sections.first.interfaces.first
          expect(intf.section).to eq(@pcapng.sections.first)
          expect(intf.packets.size).to eq(4)
          expect(intf.snaplen).to eq(0)
          packet = intf.packets.first
          expect(packet.interface).to eq(intf)
          expect(packet.data.size).to eq(packet.orig_len)
        end

        it 'yields xPB object per read packet' do
          idx = 0
          @pcapng.readfile(@file) do |pkt|
            expect(pkt).to be_a(PcapNG::EPB)
            idx += 1
          end
          expect(idx).to eq(11)
        end

        it 'reads many kinds of pcapng file' do
          %i[little big].each do |endian|
            base_dir = ::File.join(__dir__, endian == :little ? 'output_le' : 'output_be')
            PCAPNG_TEST_FILES.each do |file, sections|
              next if file == 'difficult/test202.pcapng' # specific spec below

              @pcapng.clear
              @pcapng.readfile ::File.join(base_dir, file)
              expect(@pcapng.sections[0].endian).to eq(endian)
              expect(@pcapng.sections.size).to eq(sections.size)
              sections.each_with_index do |section, i|
                expect(@pcapng.sections[i].unknown_blocks.size).to eq(section[:unknown])
                expect(@pcapng.sections[i].interfaces.size).to eq(section[:idb])
                packets = @pcapng.sections[i].interfaces.map(&:packets).flatten
                expect(packets.grep(EPB).size).to eq(section[:epb])
                expect(packets.grep(SPB).size).to eq(section[:spb])
              end
            end
          end
        end

        it 'reads a file with different sections, with different endians' do
          sections = PCAPNG_TEST_FILES['difficult/test202.pcapng']
          %i[little big].each do |endian|
            other_endian = endian == :little ? :big : :little
            base_dir = ::File.join(__dir__, endian == :little ? 'output_le' : 'output_be')

            @pcapng.clear
            @pcapng.readfile ::File.join(base_dir, 'difficult', 'test202.pcapng')

            expect(@pcapng.sections.size).to eq(sections.size)
            expect(@pcapng.sections[0].endian).to eq(endian)
            expect(@pcapng.sections[1].endian).to eq(other_endian)
            expect(@pcapng.sections[2].endian).to eq(endian)
            sections.each_with_index do |section, i|
              expect(@pcapng.sections[i].unknown_blocks.size).to eq(section[:unknown])
              expect(@pcapng.sections[i].interfaces.size).to eq(section[:idb])
              @pcapng.sections[i].unknown_blocks.each do |block|
                expect(block.endian).to eq(@pcapng.sections[i].endian)
              end
              @pcapng.sections[i].interfaces.each do |interface|
                expect(interface.endian).to eq(@pcapng.sections[i].endian)
                interface.packets.each do |packet|
                  expect(packet.endian).to eq(@pcapng.sections[i].endian)
                end
              end
              packets = @pcapng.sections[i].interfaces.map(&:packets).flatten
              expect(packets.grep(EPB).size).to eq(section[:epb])
              expect(packets.grep(SPB).size).to eq(section[:spb])
            end
          end
        end

        it 'raises when file cannot be read' do
          expect { @pcapng.readfile 'inexistent_file.pcapng' }
            .to raise_error(ArgumentError, /cannot read/)
        end
      end

      describe '#read_packet_bytes' do
        it 'returns an array of raw packets' do
          raw_packets = @pcapng.read_packet_bytes(@file)
          icmp = Packet.parse(raw_packets[2])
          expect(icmp.ip.src).to eq('192.168.1.105')
          expect(icmp.ip.dst).to eq('216.75.1.230')
          expect(icmp.icmp.type).to eq(8)
          expect(icmp.icmp.code).to eq(0)
        end
      end

      describe '#read_packets' do
        before(:all) do
          @expected = [Header::DNS] * 2 + [Header::ICMP] * 3 + [Header::ARP] * 2 +
                      [Header::TCP] * 3 + [Header::ICMP]
        end

        it 'returns an array of Packets' do
          packets = @pcapng.read_packets(@file)
          expect(packets.map { |p| p.headers.last.class }).to eq(@expected)

          pkt = packets[2]
          expect(pkt.ip.src).to eq('192.168.1.105')
          expect(pkt.ip.dst).to eq('216.75.1.230')
          expect(pkt.icmp.type).to eq(8)
          expect(pkt.icmp.code).to eq(0)
        end

        it 'yields Packet object per read packet' do
          idx = 0
          @pcapng.read_packets(@file) do |pkt|
            expect(pkt.headers.last).to be_a(@expected[idx])
            idx += 1
          end
          expect(idx).to eq(11)
        end
      end

      describe '#file_to_array' do
        it 'generates an array from object state' do
          @pcapng.readfile @file
          ary = @pcapng.file_to_array
          expect(ary).to be_a(Array)
          ary.each do |p|
            expect(p).to be_a(String)
          end
          expect(ary[0]).to eq(@pcapng.sections[0].interfaces[0].packets[0].data)
        end

        it 'generates an array from given file, clearing object state' do
          @pcapng.readfile @file
          ary = @pcapng.file_to_array(file: @file_spb)
          expect(@pcapng.sections.size).to eq(1)
          expect(@pcapng.sections[0].interfaces[0].packets[0]).to be_a(SPB)

          expect(ary).to be_a(Array)
          ary.each do |p|
            expect(p).to be_a(String)
          end
          expect(ary[0]).to eq(@pcapng.sections[0].interfaces[0].packets[0].data)
        end

        it 'generates an array with timestamps' do
          @pcapng.readfile @file
          ary = @pcapng.file_to_array(keep_timestamps: true)
          expect(ary).to be_a(Array)
          ary.each do |p|
            expect(p).to be_a(Hash)
            expect(p.keys.first).to be_a(Time)
            expect(p.values.first).to be_a(String)
          end

          packet1 = @pcapng.sections[0].interfaces[0].packets[0]
          expect(ary[0].keys.first).to eq(packet1.timestamp)
          expect(ary[0].values.first).to eq(packet1.data)
        end
      end

      describe '#to_file' do
        before(:each) { @write_file = Tempfile.new('pcapng') }
        after(:each) { @write_file.close; @write_file.unlink }

        it 'creates a file and write self to it' do
          @pcapng.readfile @file
          @pcapng.to_file @write_file.path
          @write_file.rewind
          expect(@write_file.read).to eq(::File.read(@file))
        end

        it 'appends a section to an existing file' do
          @pcapng.readfile @file
          @pcapng.to_file @write_file.path

          @pcapng.to_file @write_file.path, append: true

          @pcapng.clear
          @pcapng.readfile @write_file.path
          expect(@pcapng.sections.size).to eq(2)
          expect(@pcapng.sections[0].to_s).to eq(@pcapng.sections[1].to_s)
        end
      end

      describe '#append' do
        before(:each) { @write_file = Tempfile.new('pcapng') }
        after(:each) { @write_file.close; @write_file.unlink }

        it 'appends a section to an existing file' do
          @pcapng.readfile @file
          @pcapng.to_file @write_file.path

          @pcapng.append @write_file.path

          @pcapng.clear
          @pcapng.readfile @write_file.path
          expect(@pcapng.sections.size).to eq(2)
          expect(@pcapng.sections[0].to_s).to eq(@pcapng.sections[1].to_s)
        end
      end

      describe '#array_to_file' do
        before(:each) do
          tmpfile = Tempfile.new('packetfu')
          @tmpfilename = tmpfile.path
          tmpfile.close
          tmpfile.unlink
        end
        after(:each) { ::File.unlink @tmpfilename if ::File.exist? @tmpfilename }

        it 'gets an array of Packet objects' do
          packets = @pcapng.read_packets(@file)

          @pcapng.clear
          @pcapng.array_to_file(packets)
          @pcapng.write @tmpfilename

          @pcapng.clear
          packets2 = @pcapng.read_packets(@tmpfilename)
          expect(packets2.map(&:to_s).join).to eq(packets.map(&:to_s).join)
        end

        it 'gets a hash containing an array of Packet objects' do
          packets = @pcapng.read_packets(@file)[0..1]

          @pcapng.clear
          @pcapng.array_to_file(array: packets)
          @pcapng.write @tmpfilename

          @pcapng.clear
          packets2 = @pcapng.read_packets(@tmpfilename)
          expect(packets2.map(&:to_s).join).to eq(packets.map(&:to_s).join)
        end

        it 'gets a hash containing an array of Packet objects and a :timestamp key' do
          packets = @pcapng.read_packets(@file)[0..1]

          @pcapng.clear
          @pcapng.array_to_file(array: packets,
                                timestamp: Time.utc(2000, 1, 1),
                                ts_inc: 3600 * 24)
          @pcapng.write @tmpfilename

          @pcapng.clear
          @pcapng.readfile(@tmpfilename)
          @pcapng.sections[0].interfaces[0].packets.each_with_index do |pkt, i|
            expect(pkt.data).to eq(packets[i].to_s)
            expect(pkt.timestamp).to eq(Time.utc(2000, 1, 1 + i))
          end
        end

        it 'gets a hash containing couples of Time and Packet objects' do
          packets = @pcapng.read_packets(@file)[0..3]
          timestamp = Time.utc(2000, 1, 1)
          ts_inc = 3600 * 24 * 2
          array = []
          packets.each_with_index do |pkt, i|
            array << { (timestamp + ts_inc * i) => pkt }
          end

          @pcapng.clear
          @pcapng.array_to_file(array: array)
          @pcapng.write @tmpfilename

          @pcapng.clear
          @pcapng.readfile(@tmpfilename)
          @pcapng.sections[0].interfaces[0].packets.each_with_index do |pkt, i|
            expect(pkt.data).to eq(packets[i].to_s)
            expect(pkt.timestamp).to eq(Time.utc(2000, 1, 1 + 2 * i))
          end
        end

        it 'gets a hash containing a :file key' do
          packets = @pcapng.read_packets(@file)[0..2]

          @pcapng.clear
          @pcapng.array_to_file(array: packets, file: @tmpfilename)

          @pcapng.clear
          packets2 = @pcapng.read_packets(@tmpfilename)
          expect(packets2.map(&:to_s).join).to eq(packets.map(&:to_s).join)
        end

        it 'raises when :array argument is not an Array' do
          packets = @pcapng.read_packets(@file)[0..2]
          expect { @pcapng.array_to_file array: packets.map(&:to_s).join }
            .to raise_error(ArgumentError, /needs to be an array/)
        end

        it 'raises when argument is nor an Array neither a Hash' do
          packets = @pcapng.read_packets(@file)[0..2]
          expect { @pcapng.array_to_file packets.map(&:to_s).join }
            .to raise_error(ArgumentError, /Need either/)
        end
      end

      it '#to_s returns object as a String' do
        orig_str = binary(::File.read(@file))
        @pcapng.read orig_str
        expect(@pcapng.to_s).to eq(orig_str)

        @pcapng.clear
        orig_str = binary(::File.read(@file_spb))
        @pcapng.read orig_str
        expect(@pcapng.to_s).to eq(orig_str)
      end

      describe '#read!' do
        it 'clears object and reads a string' do
          str1 = binary(::File.read(@file))
          str2 = binary(::File.read(@file_spb))
          @pcapng.read str1

          @pcapng.read! str2
          expect(@pcapng.to_s).to eq(str2)
        end
      end
    end
  end
end
