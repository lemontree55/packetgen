require_relative 'spec_helper'

module PacketGen

  describe Packet do

    describe '.gen' do
      before(:each) do
        @pkt = Packet.gen('IP')
     end

      it 'raises on unknown protocol' do
        expect { Packet.gen 'IPOT' }.to raise_error(ArgumentError)
      end

      it 'generates a packet with one header' do
        expect(@pkt.headers.size).to eq(1)
        expect(@pkt.headers.first).to be_a(Header::IP)
      end

      it 'generates a packet with good protocol' do
        expect(@pkt.is? 'IP').to be(true)
      end

      it 'accepts options for given protocol' do
        pkt = Packet.gen('IP', src: '192.168.1.1')
        expect(pkt.ip.src).to eq('192.168.1.1')
      end

      it 'magically defines `protocol` method' do
        expect(@pkt.respond_to? :ip).to be(true)
        expect(@pkt.ip).to be_a(Header::IP)
      end

      it 'magic methods accept arguments' do
        @pkt.ip(src: '192.168.1.1', dst: '192.168.1.127')
        expect(@pkt.ip.src).to eq('192.168.1.1')
        expect(@pkt.ip.dst).to eq('192.168.1.127')
      end

      it 'magic methods raise on unknown attribute' do
        attr = :unknown_attr
        expect { @pkt.ip(attr => nil) }.to raise_error(ArgumentError).
                                            with_message(/unknown #{attr} attribute/)
      end

      it 'is called through PacketGen.gen' do
        pkt = PacketGen.gen('IP', src: '192.168.1.1')
        expect(pkt.ip.src).to eq('192.168.1.1')
      end
    end

    describe '.parse' do
      before(:each) do
        file = PcapNG::File.new
        fname = File.join(__dir__, 'pcapng', 'sample.pcapng')
        @raw_pkts = file.read_packet_bytes(fname)
      end

      it 'parses a string, guess first header and get a packet (IPv4)' do
        pkt = nil
        expect { pkt = Packet.parse(@raw_pkts.first) }.not_to raise_error
        expect(pkt).to respond_to :eth
        expect(pkt).to respond_to :ip
        expect(pkt).to respond_to :udp
        expect(pkt.eth.dst).to eq('00:03:2f:1a:74:de')
        expect(pkt.ip.ttl).to eq(128)
        expect(pkt.ip.src).to eq('192.168.1.105')
        expect(pkt.udp.sport).to eq(55261)
        expect(pkt.udp.dport).to eq(53)
        expect(pkt.udp.length).to eq(44)
        expect(pkt.udp.checksum).to eq(0x8bf8)
      end

      it 'parses a string, guess first header and get a packet (IPv6)' do
        pkt = Packet.read(File.join(__dir__, 'pcapng', 'ipv6_tcp.pcapng')).first
        expect(pkt).to respond_to :eth
        expect(pkt).to respond_to :ipv6
        expect(pkt.ipv6.version).to eq(6)
        expect(pkt.ipv6.traffic_class).to eq(0)
        expect(pkt.ipv6.flow_label).to eq(0x594ac)
        expect(pkt.ipv6.length).to eq(40)
        expect(pkt.ipv6.next).to eq(6)
        expect(pkt.ipv6.dst).to eq('2a00:1450:4007:810::2003')
      end

      it 'parses a string with first_header set to correct header' do
        pkt = nil
        expect { pkt = Packet.parse(@raw_pkts.first, first_header: 'Eth') }.
          not_to raise_error
        expect(pkt).to respond_to :eth
        expect(pkt).to respond_to :ip
        expect(pkt).to respond_to :udp
        expect(pkt.eth.dst).to eq('00:03:2f:1a:74:de')
        expect(pkt.ip.src).to eq('192.168.1.105')
        expect(pkt.udp.sport).to eq(55261)
      end

      it 'parses a string with first_header set to uncorrect header' do
        pkt = nil
        expect { pkt = Packet.parse(@raw_pkts.first, first_header: 'IP') }.
          not_to raise_error
        expect(pkt).to respond_to :ip
        expect(pkt.ip.version).to eq(0)
        expect(pkt.ip.ihl).to eq(0)
        expect(pkt.ip.tos).to eq(3)
        expect(pkt.ip.id).to eq(0x74de)
        expect(pkt.ip.protocol).to eq(0x51)
      end

      it 'is called through PacketGen.parse' do
        pkt = nil
        expect { pkt = PacketGen.parse(@raw_pkts.first) }.not_to raise_error
        expect(pkt).to respond_to :eth
        expect(pkt).to respond_to :ip
        expect(pkt).to respond_to :udp
        expect(pkt.eth.dst).to eq('00:03:2f:1a:74:de')
        expect(pkt.udp.checksum).to eq(0x8bf8)

        expect { pkt = PacketGen.parse(@raw_pkts.first, first_header: 'Eth') }.
          not_to raise_error
      end
    end

    describe '.read' do
      let(:file) { ::File.join(__dir__, 'pcapng', 'sample.pcapng') }
      let(:pcap_file) { ::File.join(__dir__, 'sample.pcap') }

      it 'reads a PcapNG file and returns a Array of Packet' do
        ary = Packet.read(file)
        expect(ary).to be_a(Array)
        expect(ary.all? { |el| el.is_a? Packet }).to be(true)
      end

      it 'reads a pcap file and returns a Array of Packet' do
        ary = Packet.read(pcap_file)
        expect(ary).to be_a(Array)
        expect(ary.all? { |el| el.is_a? Packet }).to be(true)
      end

      it 'is called through PacketGen.read' do
        ary = PacketGen.read(file)
        expect(ary).to be_a(Array)
        expect(ary.all? { |el| el.is_a? Packet }).to be(true)
      end

      it 'raises error on unknown file' do
        expect { Packet.read __FILE__ }.to raise_error(ArgumentError)
      end
    end

    describe '.write' do
      let(:file) { ::File.join(__dir__, 'pcapng', 'sample.pcapng') }

      it '.write writes a Array of Packet to a file' do
        ary = Packet.read(file)
        write_file = Tempfile.new('pcapng')
        begin
          Packet.write(write_file.path, ary)
          expect(Packet.read(write_file.path)).to eq(ary)
        ensure
          write_file.close
          write_file.unlink
        end
      end

      it 'is called through PacketGen.write' do
        ary = Packet.read(file)
        write_file = Tempfile.new('pcapng')
        begin
          PacketGen.write(write_file.path, ary)
          expect(Packet.read(write_file.path)).to eq(ary)
        ensure
          write_file.close
          write_file.unlink
        end
      end
    end

    describe '.capture', :sudo  do
      it 'captures packets using options' do
        before = Time.now
        Packet.capture(iface: 'lo', timeout: 1)
        after = Time.now
        expect(after - before).to be < 2
      end

      it 'yields captures packets' do
        yielded_packets = []
        packets = nil
        cap_thread = Thread.new do
          packets = Packet.capture(iface: 'lo', timeout: 1) { |pkt| yielded_packets << pkt }
        end
        sleep 0.1
        system 'ping -c 2 127.0.0.1 > /dev/null'
        cap_thread.join(0.5)
        expect(yielded_packets.size).to eq(packets.size)
        expect(yielded_packets).to eq(packets)
      end
    end

    describe '#add' do
      before(:each) do
        @pkt = Packet.gen('IP')
      end

      it 'adds another protocol in packet' do
        @pkt.add 'IP'
        expect(@pkt.headers.size).to eq(2)
        expect(@pkt.headers[1]).to be_a(Header::IP)
      end

      it 'sets added protocol header as body of previous header' do
        2.times { @pkt.add 'IP' }
        expect(@pkt.ip(1).body).to eq(@pkt.ip(2))
        expect(@pkt.ip(2).body).to eq(@pkt.ip(3))
        expect(@pkt.ip(3).body).to be_empty
      end

      it 'sets protocol information in previous header' do
        expect(@pkt.ip.protocol).to eq(0)
        @pkt.add 'IP'
        expect(@pkt.ip.protocol).to eq(Header::IP.known_headers[Header::IP].first.value)
        expect(@pkt.ip(2).protocol).to eq(0)
      end

      it 'raises on unknown protocol' do
        expect { @pkt.add 'IPOT' }.to raise_error(ArgumentError)
      end

      it 'raises on unknown association' do
        expect { @pkt.add 'Eth' }.to raise_error(ArgumentError, /IP\.bind_layer\(.*Eth/)
      end
    end

    describe '#is?' do
      before(:each) do
        @pkt = Packet.gen('IP')
      end

      it 'returns true for contained header type' do
        expect(@pkt.is? 'IP').to be(true)
      end

      it 'returns false for absent header type' do
        expect(@pkt.is? 'Eth').to be(false)
      end

      it 'raises on unknown protocol' do
        expect { @pkt.is? 'IPOT' }.to raise_error(ArgumentError)
      end
    end

    describe '#calc_checksum' do
      it 'recalculates packet checksums' do
        pkt = Packet.gen('Eth').add('IP', src: '1.1.1.1', dst: '2.2.2.2', id: 0xffff).
              add('UDP', sport: 45768, dport: 80)
        pkt.body = 'abcdef'
        expect(pkt.ip.checksum).to eq(0)
        expect(pkt.udp.checksum).to eq(0)
        pkt.calc_length
        pkt.calc_checksum
        expect(pkt.ip.checksum).to eq(0x74c6)
        expect(pkt.udp.checksum).to eq(0x1c87)
      end
    end

    describe '#to_w' do
      let(:pkt) { Packet.gen('Eth', dst: 'ff:ff:ff:ff:ff:ff', src: 'ff:ff:ff:ff:ff:ff').
                         add('IP', src: '128.1.2.3', dst: '129.1.2.3') }

      it 'sends a packet on wire', :sudo do
        Thread.new { sleep 0.1; pkt.to_w('lo') }
        packets = Packet.capture(iface: 'lo', max: 1,
                                 filter: 'ether dst ff:ff:ff:ff:ff:ff',
                                 timeout: 2)
        packet = packets.first
        expect(packet.is? 'Eth').to be(true)
        expect(packet.eth.dst).to eq('ff:ff:ff:ff:ff:ff')
        expect(packet.eth.src).to eq('ff:ff:ff:ff:ff:ff')
        expect(packet.eth.ethertype).to eq(0x0800)
        expect(packet.ip.dst).to eq('129.1.2.3')
      end

      it 'calculates sum and length before sending a packet on wire', :sudo do
        pkt.body = '123'
        pkt.ip.id = 0   # to remove randomness on checksum computation

        Thread.new { sleep 0.1; pkt.to_w('lo', calc: true) }
        packets = Packet.capture(iface: 'lo', max: 1,
                                 filter: 'ether dst ff:ff:ff:ff:ff:ff',
                                 timeout: 2)
        packet = packets.first
        expect(packet.ip.src).to eq('128.1.2.3')
        expect(packet.ip.dst).to eq('129.1.2.3')
        expect(packet.ip.length).to eq(23)
        expect(packet.ip.checksum).to eq(0x75df)
      end

      it 'sends packet multiple times', :sudo do
        Thread.new  { sleep 0.1; pkt.to_w('lo', number: 5, interval: 0.1) }
        packets = Packet.capture(iface: 'lo', max: 5,
                                 filter: 'ether dst ff:ff:ff:ff:ff:ff',
                                 timeout: 1)

        expect(packets.length).to eq(5)
      end

      it 'raises when first header do not implement #to_w' do
        pkt = Packet.gen('UDP')
        expect { pkt.to_w }.to raise_error(WireError, /don't known how to send/)
      end
    end

    describe '#to_f' do
      before(:each) { @write_file = Tempfile.new('packet') }
      after(:each) { @write_file.close; @write_file.unlink }

      it 'writes packet as a PcapNG file' do
        pkt1 = Packet.gen('Eth').add('IP', src: '1.1.1.1', dst: '2.2.2.2', id: 0xffff).
                add('UDP', sport: 45768, dport: 80)
        pkt1.to_f(@write_file.path)

        pkt2 = Packet.read(@write_file.path).first
        expect(pkt2).to eq(pkt1)
      end
    end

    describe '#to_s' do
      it 'returns a binary string from complete packet' do
        pkt = Packet.gen('Eth', dst: '00:01:02:03:04:05').add('IP')
        idx = [pkt.ip.id].pack('n')
        expected = force_binary("\x00\x01\x02\x03\x04\x05" \
                                          "\x00\x00\x00\x00\x00\x00\x08\x00" \
                                          "\x45\x00\x00\x14#{idx}\x00\x00" \
                                          "\x40\x00\x00\x00" \
                                          "\x7f\x00\x00\x01\x7f\x00\x00\x01")
        expect(pkt.to_s).to eq(expected)
      end
    end

    describe '#encapsulate' do
      it 'encapsulates a packet in another one' do
        inner_pkt = Packet.gen('IP', src: '10.0.0.1', dst: '10.1.0.1').
                    add('UDP', sport: 45321, dport: 53, body: 'abcd')
        inner_pkt.calc

        outer_pkt = Packet.gen('IP', src: '45.216.4.3', dsy: '201.123.200.147')
        outer_pkt.encapsulate inner_pkt
        outer_pkt.calc
        expect(outer_pkt.ip(2)).to eq(inner_pkt.ip)
        expect(outer_pkt.udp).to eq(inner_pkt.udp)
        expect(outer_pkt.body).to eq('abcd')
      end
    end

    describe '#decapsulate' do
      it 'removes first header from packet' do
        pkt = PacketGen.gen('IP', src: '1.0.0.1', dst: '1.0.0.2').
              add('IP', src: '10.0.0.1', dst: '10.0.0.2').
              add('ICMP', type: 8, code: 0)
        pkt.decapsulate(pkt.ip)
        expect(pkt.headers.size).to eq(2)
        expect(pkt.is? 'IP').to be(true)
        expect(pkt.is? 'ICMP').to be(true)
        expect(pkt.ip.src).to eq('10.0.0.1')
      end

      it 'removes a header from packet' do
        pkt = Packet.gen('Eth', dst: '00:00:00:00:00:01', src: '00:01:02:03:04:05').
              add('IP', src: '1.0.0.1', dst: '1.0.0.2').
              add('IP', src: '10.0.0.1', dst: '10.0.0.2').
              add('ICMP', type: 8, code: 0)
        pkt.decapsulate(pkt.ip)
        expect(pkt.headers.size).to eq(3)
        expect(pkt.is? 'Eth').to be(true)
        expect(pkt.is? 'IP').to be(true)
        expect(pkt.is? 'ICMP').to be(true)
        expect(pkt.ip.src).to eq('10.0.0.1')
      end

      it 'removes multiple headers' do
        pkt = Packet.gen('Eth', dst: '00:00:00:00:00:01', src: '00:01:02:03:04:05').
              add('IP', src: '1.0.0.1', dst: '1.0.0.2').
              add('IP', src: '10.0.0.1', dst: '10.0.0.2').
              add('ICMP', type: 8, code: 0)
        pkt.decapsulate(pkt. eth, pkt.ip)
        expect(pkt.headers.size).to eq(2)
        expect(pkt.is? 'IP').to be(true)
        expect(pkt.is? 'ICMP').to be(true)
        expect(pkt.ip.src).to eq('10.0.0.1')
      end

      it 'raises if removed header results to an unknown binding' do
        pkt = Packet.gen('Eth', dst: '00:00:00:00:00:01', src: '00:01:02:03:04:05').
              add('IP', src: '10.0.0.1', dst: '10.0.0.2').
              add('ICMP', type: 8, code: 0)
        expect { pkt.decapsulate pkt.ip }.to raise_error(FormatError)
      end
    end
  end
end
