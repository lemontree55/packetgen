# frozen_string_literal: true

require_relative 'spec_helper'

module PGTestModule
  class TestHeader < PacketGen::Header::Base
    define_attr :field1, BinStruct::Int32
    define_attr :field2, BinStruct::Int32
  end
end

module PacketGen
  describe Header do
    it '.all returns all header classes' do
      expect(Header.all).to include(Header::Eth, Header::IP, Header::ICMP, Header::ARP,
                                    Header::IPv6, Header::ICMPv6, Header::UDP,
                                    Header::TCP, Header::SCTP)
      expect(Header.all.size).to eq(54)
    end

    describe '.add_class' do
      after { Header.remove_class PGTestModule::TestHeader }

      it 'adds a foreign header' do
        expect(Header.all).not_to include(PGTestModule::TestHeader)
        Header.add_class PGTestModule::TestHeader
        expect(Header.all).to include(PGTestModule::TestHeader)
      end

      it 'adds a class only once' do
        Header.add_class PGTestModule::TestHeader
        Header.add_class PGTestModule::TestHeader
        expect(Header.all).to include(PGTestModule::TestHeader)
        nb_th = Header.all.select { |hdr| hdr == PGTestModule::TestHeader }.size
        expect(nb_th).to eq(1)
      end
    end

    describe '.remove_class' do
      before { Header.add_class PGTestModule::TestHeader }
      after { Header.remove_class PGTestModule::TestHeader }

      it 'removes a foreign header from known headers' do
        expect(Header.all).to include(PGTestModule::TestHeader)
        Header.remove_class PGTestModule::TestHeader
        expect(Header.all).not_to include(PGTestModule::TestHeader)
      end
    end
  end

  context 'with foreign headers' do
    before(:all) do
      PacketGen::Header.add_class(PGTestModule::TestHeader)
      PacketGen::Header::IP.bind(PGTestModule::TestHeader, protocol: 254)
    end

    after(:all) do
      PacketGen::Header.remove_class(PGTestModule::TestHeader)
    end

    it 'may be used by Packet.gen' do
      pkt = nil
      expect { pkt = PacketGen.gen('TestHeader', field1: 1) }
        .not_to raise_error
      expect(pkt.headers.size).to eq(1)
      expect(pkt.headers.first).to be_a(PGTestModule::TestHeader)
      expect(pkt.testheader).to be_a(PGTestModule::TestHeader)
      expect(pkt.testheader.field1.to_i).to eq(1)
    end

    it 'may be used by Packet#add' do
      pkt = PacketGen.gen('IP')
      expect { pkt.add('TestHeader', field2: 2) }.not_to raise_error
      expect(pkt.headers.size).to eq(2)
      expect(pkt.headers.first).to be_a(Header::IP)
      expect(pkt.headers.last).to be_a(PGTestModule::TestHeader)
      expect(pkt.testheader).to be_a(PGTestModule::TestHeader)
      expect(pkt.testheader.field2.to_i).to eq(2)
    end

    it 'may be used while parsing' do
      field1 = rand(2**32)
      field2 = rand(2**32)
      pkt = PacketGen.gen('IP', protocol: 254, body: [field1, field2].pack('N2'))

      new_pkt = PacketGen.parse(pkt.to_s)
      expect(new_pkt.headers.size).to eq(2)
      expect(new_pkt.is?('IP')).to be(true)
      expect(new_pkt.is?('TestHeader')).to be(true)
      expect(new_pkt.testheader).to be_a(PGTestModule::TestHeader)
      expect(new_pkt.testheader.field1.to_i).to eq(field1)
      expect(new_pkt.testheader.field2.to_i).to eq(field2)
    end
  end
end
