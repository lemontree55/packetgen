# frozen_string_literal: true

require 'tempfile'
require_relative '../spec_helper'
require_relative 'file_spec_helper'

# Clear options attributes from a PcapNG::Block
def block_clear_options(blk)
  blk.options = ''
  blk.recalc_block_len
end

# Clear options attributes from a PcapNG::File
def file_clear_options(file)
  file.sections.each do |sec|
    block_clear_options(sec)
    sec.interfaces.each do |itf|
      block_clear_options(itf)
    end
  end
end

module PacketGen
  module PcapNG
    describe File do
      before(:all) do
        @file = ::File.join(__dir__, 'sample.pcapng')
        @file_spb = ::File.join(__dir__, 'sample-spb.pcapng')
      end
      let(:pcapng) { File.new }

      describe '#readfile' do
        it 'reads a Pcap-NG file' do
          pcapng.readfile @file
          expect(pcapng.sections.size).to eq(1)
          expect(pcapng.sections[0].unknown_blocks.size).to eq(0)

          expect(pcapng.sections.first.interfaces.size).to eq(1)
          intf = pcapng.sections.first.interfaces.first
          expect(intf.section).to eq(pcapng.sections.first)

          expect(intf.packets.size).to eq(11)
          packet = intf.packets.first
          expect(packet.interface).to eq(intf)
        end

        it 'reads a Pcap-NG file with Simple Packet blocks' do
          pcapng.readfile @file_spb
          expect(pcapng.sections.size).to eq(1)
          expect(pcapng.sections[0].unknown_blocks.size).to eq(0)
          expect(pcapng.sections.first.interfaces.size).to eq(1)
          intf = pcapng.sections.first.interfaces.first
          expect(intf.section).to eq(pcapng.sections.first)
          expect(intf.packets.size).to eq(4)
          expect(intf.snaplen).to eq(0)
          packet = intf.packets.first
          expect(packet.interface).to eq(intf)
          expect(packet.data.size).to eq(packet.orig_len)
        end

        it 'yields xPB object per read packet' do
          idx = 0
          pcapng.readfile(@file) do |pkt|
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

              pcapng.clear
              pcapng.readfile ::File.join(base_dir, file)
              expect(pcapng.sections[0].endian).to eq(endian)
              expect(pcapng.sections.size).to eq(sections.size)
              sections.each_with_index do |section, i|
                expect(pcapng.sections[i].unknown_blocks.size).to eq(section[:unknown])
                expect(pcapng.sections[i].interfaces.size).to eq(section[:idb])
                packets = pcapng.sections[i].interfaces.map(&:packets).flatten
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

            pcapng.clear
            pcapng.readfile ::File.join(base_dir, 'difficult', 'test202.pcapng')

            expect(pcapng.sections.size).to eq(sections.size)
            expect(pcapng.sections[0].endian).to eq(endian)
            expect(pcapng.sections[1].endian).to eq(other_endian)
            expect(pcapng.sections[2].endian).to eq(endian)
            sections.each_with_index do |section, i|
              expect(pcapng.sections[i].unknown_blocks.size).to eq(section[:unknown])
              expect(pcapng.sections[i].interfaces.size).to eq(section[:idb])
              pcapng.sections[i].unknown_blocks.each do |block|
                expect(block.endian).to eq(pcapng.sections[i].endian)
              end
              pcapng.sections[i].interfaces.each do |interface|
                expect(interface.endian).to eq(pcapng.sections[i].endian)
                interface.packets.each do |packet|
                  expect(packet.endian).to eq(pcapng.sections[i].endian)
                end
              end
              packets = pcapng.sections[i].interfaces.map(&:packets).flatten
              expect(packets.grep(EPB).size).to eq(section[:epb])
              expect(packets.grep(SPB).size).to eq(section[:spb])
            end
          end
        end

        it 'raises when file cannot be read' do
          expect { pcapng.readfile 'inexistent_file.pcapng' }
            .to raise_error(ArgumentError, /cannot read/)
        end
      end

      describe '#read_packet_bytes' do
        it 'returns an array of raw packets' do
          raw_packets = pcapng.read_packet_bytes(@file)
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
          packets = pcapng.read_packets(@file)
          expect(packets.map { |p| p.headers.last.class }).to eq(@expected)

          pkt = packets[2]
          expect(pkt.ip.src).to eq('192.168.1.105')
          expect(pkt.ip.dst).to eq('216.75.1.230')
          expect(pkt.icmp.type).to eq(8)
          expect(pkt.icmp.code).to eq(0)
        end

        it 'yields Packet object per read packet' do
          idx = 0
          pcapng.read_packets(@file) do |pkt|
            expect(pkt.headers.last).to be_a(@expected[idx])
            idx += 1
          end
          expect(idx).to eq(11)
        end
      end

      describe '#to_a' do
        it 'generates an array from object state' do
          pcapng.readfile @file
          ary = pcapng.to_a
          expect(ary).to be_a(Array)
          ary.each do |p|
            expect(p).to be_a(Packet)
          end
          expect(ary[0]).to eq(Packet.parse(pcapng.sections[0].interfaces[0].packets[0].data))
        end
      end

      describe '#to_h' do
        it 'generates a hash with timestamps as keys and packets as values' do
          pcapng.readfile @file
          hsh = pcapng.to_h
          expect(hsh).to be_a(Hash)
          hsh.each do |tstp, pkt|
            expect(tstp).to be_a(Time)
            expect(pkt).to be_a(Packet)
          end
          expect(hsh.keys.first).to eq(Time.utc(2009, 10, 11, 19, 29, 6.244202r))
          expect(hsh.values.first).to eq(Packet.parse(pcapng.sections[0].interfaces[0].packets[0].data))
        end

        it 'only embeds packets from EPB blocks in resulting hash' do
          pcapng.readfile(::File.join(__dir__, '..', 'header', 'dhcp.pcapng'))
          idb = pcapng.sections.first.interfaces.first
          # Replace 4th block (DHCP ACK packet) by an SPB one
          data = idb.packets[3].data
          spb = SPB.new(data: data, orig_len: data.size)
          spb.recalc_block_len
          idb.packets[3] = spb

          # Check 4th message (ACK one) is not present
          hsh = pcapng.to_h
          expect(hsh.values.size).to eq(3)
          hsh.values.each_with_index do |pkt, i|
            expect(pkt.dhcp.options.first.to_human).to eq("type:message-type,length:1,value:#{i + 1}")
          end
        end
      end

      describe '#to_file' do
        before(:each) { @write_file = Tempfile.new('pcapng') }
        after(:each) { @write_file.close; @write_file.unlink }

        it 'creates a file and write self to it' do
          pcapng.readfile @file
          pcapng.to_file @write_file.path
          @write_file.rewind
          expect(@write_file.read).to eq(::File.read(@file))
        end

        it 'appends a section to an existing file' do
          pcapng.readfile @file
          pcapng.to_file @write_file.path

          pcapng.to_file @write_file.path, append: true

          pcapng.clear
          pcapng.readfile @write_file.path
          expect(pcapng.sections.size).to eq(2)
          expect(pcapng.sections[0].to_s).to eq(pcapng.sections[1].to_s)
        end
      end

      describe '#append' do
        before(:each) { @write_file = Tempfile.new('pcapng') }
        after(:each) { @write_file.close; @write_file.unlink }

        it 'appends a section to an existing file' do
          pcapng.readfile @file
          pcapng.to_file @write_file.path

          pcapng.append @write_file.path

          pcapng.clear
          pcapng.readfile @write_file.path
          expect(pcapng.sections.size).to eq(2)
          expect(pcapng.sections[0].to_s).to eq(pcapng.sections[1].to_s)
        end
      end


      describe '#read_array' do
        let(:ref_pcapng) { file = File.new; file.readfile(@file_spb); file }

        it 'gets an array of Packet objects' do
          file_clear_options(ref_pcapng)
          packets = ref_pcapng.to_a

          pcapng.read_array(packets)
          expect(pcapng.to_s).to eq(ref_pcapng.to_s)
        end

        it 'gets a timestamp and a ts_inc value and generates EPB blocks' do
          file_clear_options(ref_pcapng)
          packets = ref_pcapng.to_a

          start_time = Time.now
          pcapng.read_array(packets, timestamp: start_time, ts_inc: 0.1r)
          expect(pcapng.sections.first.inspect).to eq(ref_pcapng.sections.first.inspect)

          idb = pcapng.sections.first.interfaces.first
          ref_idb = ref_pcapng.sections.first.interfaces.first
          expect(idb.inspect).to eq(ref_idb.inspect)
          idb.packets.each_with_index do |pkt, i|
            expect(pkt).to be_a(EPB)
            expect(pkt.timestamp).to be_within(2 * idb.ts_resol).of(start_time + i * 0.1r)
            expect(pkt.data).to eq(ref_idb.packets[i].data)
          end
        end

        it 'generates SPB blocks when timestamp is nil' do
          packets = ref_pcapng.to_a
          pcapng.read_array(packets, ts_inc: 0.1r)
          pcapng.sections.first.interfaces.first.packets.each do |pkt|
            expect(pkt).to be_a(SPB)
          end
        end

        it 'generates SPB blocks when ts_inc is nil' do
          packets = ref_pcapng.to_a
          pcapng.read_array(packets, timestamp: Time.now)
          pcapng.sections.first.interfaces.first.packets.each do |pkt|
            expect(pkt).to be_a(SPB)
          end
        end
      end

      describe '#read_hash' do
        let(:ref_pcapng) { file = File.new; file.readfile(@file); file }

        it 'gets a hash of timestamps=>packets' do
          file_clear_options(ref_pcapng)
          hsh = ref_pcapng.to_h
          pcapng.read_hash(hsh)
          pcapng.sections.first.interfaces.first.snaplen = 65535

          expect(pcapng.to_s).to eq(ref_pcapng.to_s)
        end

        it 'generates EPB packet blocks' do
          hsh = ref_pcapng.to_h
          pcapng.read_hash(hsh)
          pcapng.sections.first.interfaces.first.packets.each do |pkt|
            expect(pkt).to be_a(EPB)
          end
        end
      end

      it '#to_s returns object as a String' do
        orig_str = binary(::File.read(@file))
        pcapng.read orig_str
        expect(pcapng.to_s).to eq(orig_str)

        pcapng.clear
        orig_str = binary(::File.read(@file_spb))
        pcapng.read orig_str
        expect(pcapng.to_s).to eq(orig_str)
      end

      describe '#read!' do
        it 'clears object and reads a string' do
          str1 = binary(::File.read(@file))
          str2 = binary(::File.read(@file_spb))
          pcapng.read str1

          pcapng.read! str2
          expect(pcapng.to_s).to eq(str2)
        end
      end
    end
  end
end
