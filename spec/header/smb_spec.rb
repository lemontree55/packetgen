require_relative '../spec_helper'

module PacketGen
  module Header

    pkts = PcapNG::File.new.read_packets(File.join(__dir__, 'smb.pcapng'))

    describe SMB do
      describe 'binding' do
        it 'in NetBIOS packets' do
          expect(NetBIOS::Session).to know_header(SMB).with(body: SMB::MARKER)
          expect(SMB).to know_header(SMB::Blocks)
        end
      end

      describe '#initialize' do
        it 'creates a SMB header with default values' do
          smb = SMB.new
          expect(smb.protocol).to eq(SMB::MARKER)
          expect(smb.command).to eq(4)
          expect(smb[:command].to_human).to eq('close')
          expect(smb.status).to eq(0)
          expect(smb.flags).to eq(0)
          expect(smb.flags2).to eq(0)
          expect(smb.pid_high).to eq(0)
          expect(smb.security_features).to eq(0)
          expect(smb.reserved).to eq(0)
          expect(smb.tid).to eq(0)
          expect(smb.pid).to eq(0)
          expect(smb.uid).to eq(0)
          expect(smb.mid).to eq(0)
        end
      end

      describe '#read' do
        it 'sets header from a string' do
          smb = SMB.new
          str = (0...smb.sz).to_a.pack('C*')
          smb.read str
          expect(smb.protocol).to eq("\x00\x01\x02\x03")
          expect(smb.command).to eq(4)
          expect(smb.status).to eq(0x08070605)
          expect(smb.flags).to eq(9)
          expect(smb.flags2).to eq(0x0b0a)
          expect(smb.pid_high).to eq(0x0d0c)
          expect(smb.security_features).to eq(0x1514131211100f0e)
          expect(smb.reserved).to eq(0x1716)
          expect(smb.tid).to eq(0x1918)
          expect(smb.pid).to eq(0x1b1a)
          expect(smb.uid).to eq(0x1d1c)
          expect(smb.mid).to eq(0x1f1e)
        end

        it 'parses a SMB packet' do
          pkt = pkts.first
          expect(pkt.is? 'TCP').to be(true)
          expect(pkt.is? 'NetBIOS::Session').to be(true)
          expect(pkt.is? 'SMB').to be(true)
          expect(pkt.smb.protocol).to eq(SMB::MARKER)
          expect(pkt.smb[:command].to_human).to eq('echo')
          expect(pkt.smb.status).to eq(0)
          expect(pkt.smb.flags).to eq(0x18)
          expect(pkt.smb.flags_reply?).to be(false)
          expect(pkt.smb.flags2).to eq(0xc843)
          expect(pkt.smb.pid_high).to eq(0)
          expect(pkt.smb.security_features).to eq(0)
          expect(pkt.smb.reserved).to eq(0)
          expect(pkt.smb.tid).to eq(0)
          expect(pkt.smb.pid).to eq(0)
          expect(pkt.smb.uid).to eq(0)
          expect(pkt.smb.mid).to eq(13)
          expect(pkt.smb.body).to be_a(SMB::Blocks)
          expect(pkt.smb_blocks.word_count).to eq(1)
          expect(pkt.smb_blocks.words.map(&:to_i)).to eq([1])
          expect(pkt.smb_blocks.byte_count).to eq(16)
          expect(pkt.smb_blocks.bytes.map(&:to_i)).to eq([0] * 16)
        end
      end
    end

    describe SMB::TransRequest do
      it 'parses a SMB COM_TRANSACTION request packet' do
        pkt = pkts[5]
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB').to be(true)
        expect(pkt.smb[:command].to_human).to eq('trans')
        expect(pkt.smb.flags_reply?).to be(false)
        expect(pkt.is? 'SMB::TransRequest').to be(true)
        expect(pkt.smb.body).to be_a(SMB::TransRequest)
        expect(pkt.smb_transrequest.word_count).to eq(16)
        expect(pkt.smb_transrequest.total_param_count).to eq(0)
        expect(pkt.smb_transrequest.total_data_count).to eq(72)
        expect(pkt.smb_transrequest.max_param_count).to eq(0)
        expect(pkt.smb_transrequest.max_data_count).to eq(4280)
        expect(pkt.smb_transrequest.max_setup_count).to eq(0)
        expect(pkt.smb_transrequest.rsv1).to eq(0)
        expect(pkt.smb_transrequest.flags).to eq(0)
        expect(pkt.smb_transrequest.timeout).to eq(0)
        expect(pkt.smb_transrequest.rsv2).to eq(0)
        expect(pkt.smb_transrequest.param_count).to eq(0)
        expect(pkt.smb_transrequest.param_offset).to eq(84)
        expect(pkt.smb_transrequest.data_count).to eq(72)
        expect(pkt.smb_transrequest.data_offset).to eq(84)
        expect(pkt.smb_transrequest.setup_count).to eq(2)
        expect(pkt.smb_transrequest.setup.map(&:to_i)).to eq([38, 30_255])
        expect(pkt.smb_transrequest.byte_count).to eq(89)
        expect(pkt.smb_transrequest.name).to eq("\\PIPE\\".encode('UTF-16LE'))
        expect(pkt.smb_transrequest.pad1.size).to eq(2)
      end
    end

    describe SMB::TransResponse do
      it 'parses a SMB COM_TRANSACTION response packet' do
        pkt = pkts[6]
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB').to be(true)
        expect(pkt.smb[:command].to_human).to eq('trans')
        expect(pkt.smb.flags_reply?).to be(true)
        expect(pkt.is? 'SMB::TransResponse').to be(true)
        expect(pkt.smb.body).to be_a(SMB::TransResponse)
        expect(pkt.smb_transresponse.word_count).to eq(10)
        expect(pkt.smb_transresponse.total_param_count).to eq(0)
        expect(pkt.smb_transresponse.total_data_count).to eq(68)
        expect(pkt.smb_transresponse.rsv1).to eq(0)
        expect(pkt.smb_transresponse.param_count).to eq(0)
        expect(pkt.smb_transresponse.param_offset).to eq(56)
        expect(pkt.smb_transresponse.param_displacement).to eq(0)
        expect(pkt.smb_transresponse.data_count).to eq(68)
        expect(pkt.smb_transresponse.data_offset).to eq(56)
        expect(pkt.smb_transresponse.data_displacement).to eq(0)
        expect(pkt.smb_transresponse.setup_count).to eq(0)
        expect(pkt.smb_transresponse.rsv2).to eq(0)
        expect(pkt.smb_transresponse.setup.empty?).to be(true)
        expect(pkt.smb_transresponse.byte_count).to eq(69)
        expect(pkt.smb_transresponse.pad1.size).to eq(1)
      end
    end
  end
end
