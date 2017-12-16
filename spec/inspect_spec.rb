require 'spec_helper'

module PacketGen
  describe Inspect do
    describe '.inspect_attribute' do
      it 'return a formatted string for a Types::Int attribute' do
        int8 = Types::Int8.new(52)
        inspect = Inspect.inspect_attribute('my_int8', int8)
        expect(inspect).to eq("            Int8      my_int8: 52         (0x34)\n")

        int16 = Types::Int16.new(45)
        inspect = Inspect.inspect_attribute('my_int16', int16)
        expect(inspect).to eq("           Int16     my_int16: 45         (0x002d)\n")

        enum = Types::Int32leEnum.new({'one' => 1, 'two' => 2})
        inspect = Inspect.inspect_attribute('my_enum', enum)
        expect(inspect).to eq("     Int32leEnum      my_enum: one        (0x00000001)\n")
      end

      it 'return a formatted string for an attribute responding to #to_human' do
        oui = Types::OUI.new(b2: 0x45, b1: 0xfe, b0: 0x12)
        inspect = Inspect.inspect_attribute('my_oui', oui)
        expect(inspect).to eq("             OUI       my_oui: 45:fe:12\n")
      end

      it 'return a formatted string for another attribute type' do
        str = Types::String.new.read('abc')
        inspect = Inspect.inspect_attribute('my_str', str)
        expect(inspect).to eq("          String       my_str: \"abc\"\n")

        intstr = Types::IntString.new(string: 'abc')
        inspect = Inspect.inspect_attribute('my_str', intstr)
        expect(inspect).to eq("       IntString       my_str: \"abc\"\n")
      end
    end

    describe '.inspect_asn1_attribute' do
      it 'returns a formatted string for a RASN1::Types::Enumerated' do
        enum = RASN1::Types::Enumerated.new(enum: { one: 1, two: 2})
        enum.value = 2
        inspect = Inspect.inspect_asn1_attribute('my_enum', enum)
        expect(inspect).to eq("      ENUMERATED      my_enum: two        (0x02)\n")
      end

      it 'returns a formatted string for a RASN1::Types::Integer' do
        int = RASN1::Types::Integer.new
        int.value = 12_345_678_901
        inspect = Inspect.inspect_asn1_attribute('my_int', int)
        expect(inspect).to eq("         INTEGER       my_int: 12345678901 (0x02dfdc1c35)\n")
      end

      it 'returns a formatted string for a RASN1::Model' do
        model = Header::SNMP::Bulk.new
        inspect = Inspect.inspect_asn1_attribute('my_model', model)
        expect(inspect).to eq("            Bulk     my_model: SEQUENCE\n")
      end

      it 'returns a formatted string for an other type' do
        os = RASN1::Types::OctetString.new
        os.value = "abcd"
        inspect = Inspect.inspect_asn1_attribute('my_str', os)
        expect(inspect).to eq("    OCTET STRING       my_str: \"abcd\"\n")

        bool = RASN1::Types::Boolean.new(true)
        inspect = Inspect.inspect_asn1_attribute('bool', bool)
        expect(inspect).to eq("         BOOLEAN         bool: \"true\"\n")
      end
    end

    describe '.inspect_body' do
      it 'returns an empty string when body is nil' do
        expect(Inspect.inspect_body(nil)).to eq('')
      end

      it 'returns an empty string when body is an empty string' do
        expect(Inspect.inspect_body('')).to eq('')
      end

      it 'returns a string for body' do
        body = (0..17).to_a.pack('C*') << (0x2a..0x2c).to_a.pack('C*')
        str = Inspect.inspect_body(body)
        expected = '---- Body ' << '-' * 60 << "\n"
        expected << " 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15\n"
        expected << '-' * 70 << "\n"
        expected << " 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
        expected << '  ' << '.' * 16 << "\n"
        expected << " 10 11 2a 2b 2c"
        expected << ' ' * 35 << "..*+,\n"
        expected << '-' * 70 << "\n"
        expect(str).to eq(expected)
      end
    end
  end
end
