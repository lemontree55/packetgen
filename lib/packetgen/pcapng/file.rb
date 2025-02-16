# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module PcapNG
    # PcapNG::File is a complete Pcap-NG file handler.
    # @author Sylvain Daubert
    class File # rubocop:disable Metrics/ClassLength
      # Known link types
      KNOWN_LINK_TYPES = {
        LINKTYPE_ETHERNET => 'Eth',
        LINKTYPE_IEEE802_11 => 'Dot11',
        LINKTYPE_IEEE802_11_RADIOTAP => 'RadioTap',
        LINKTYPE_PPI => 'PPI',
        LINKTYPE_IPV4 => 'IP',
        LINKTYPE_IPV6 => 'IPv6'
      }.freeze

      # @private
      BLOCK_TYPES = PcapNG.constants(false).select { |c| c.to_s.include?('_TYPE') }.to_h do |c|
        type_value = PcapNG.const_get(c).to_i
        klass = PcapNG.const_get(c.to_s.delete_suffix('_TYPE'))
        [type_value, klass]
      end.freeze

      # Get file sections
      # @return [Array]
      attr_accessor :sections

      def initialize
        @sections = []
      end

      # Read a string to populate the object. Note that this appends new blocks to
      # the Pcapng::File object.
      # @param [String] str
      # @return [self]
      def read(str)
        str = str.b unless str.encoding == Encoding::BINARY
        io = StringIO.new(str)
        parse_section(io)
        self
      end

      # Clear the contents of the Pcapng::File prior to reading in a new string.
      # This string should contain a Section Header Block and an Interface Description
      # Block to create a conform pcapng file.
      # @param [String] str
      # @return [self]
      def read!(str)
        clear
        read(str)
      end

      # Read a given file and analyze it.
      # If given a block, it will yield PcapNG::EPB or PcapNG::SPB objects.
      # This is the only way to get packet timestamps.
      # @param [String] fname pcapng file name
      # @yieldparam [EPB,SPB] block
      # @return [Integer] return number of yielded blocks (only if a block is given)
      # @raise [ArgumentError] cannot read +fname+
      def readfile(fname, &blk)
        raise ArgumentError, "cannot read file #{fname}" unless ::File.readable?(fname)

        ::File.open(fname, 'rb') { |f| parse_section(f) until f.eof? }
        return unless blk

        count = 0
        each_packet_with_interface do |pkt, _itf|
          count += 1
          yield pkt
        end
        count
      end

      # Give an array of raw packets (raw data from packets).
      # If a block is given, yield raw packet data from the given file.
      # @overload read_packet_bytes(fname)
      #  @param [String] fname pcapng file name
      #  @return [Array] array of packet raw data
      # @overload read_packet_bytes(fname)
      #  @param [String] fname pcapng file name
      #  @yieldparam [String] raw packet raw data
      #  @yieldparam [Integer] interface's link_type from which packet was captured
      #  @return [Integer] number of packets
      # @raise [ArgumentError] cannot read +fname+
      def read_packet_bytes(fname, &blk)
        packets = [] unless blk

        count = readfile(fname) do |packet|
          if blk
            yield packet.data.to_s, packet.interface.link_type
          else
            packets << packet.data.to_s
          end
        end

        blk ? count : packets
      end

      # Return an array of parsed packets.
      # If a block is given, yield parsed packets from the given file.
      # @overload read_packets(fname)
      #  @param [String] fname pcapng file name
      #  @return [Array<Packet>]
      # @overload read_packets(fname)
      #  @param [String] fname pcapng file name
      #  @yieldparam [Packet] packet
      #  @return [Integer] number of packets
      # @raise [ArgumentError] cannot read +fname+
      def read_packets(fname, &blk)
        packets = [] unless blk

        count = read_packet_bytes(fname) do |packet, link_type|
          parsed_pkt = parse_packet(packet, link_type)
          if blk
            yield parsed_pkt
          else
            packets << parsed_pkt
          end
        end

        blk ? count : packets
      end

      # Return the object as a String
      # @return [String]
      def to_s
        @sections.map(&:to_s).join
      end

      # Clear the contents of the Pcapng::File.
      # @return [void]
      def clear
        @sections.clear
      end

      # Translates a {File} into an array of packets.
      # @return [Array<Packet>]
      # @since 3.1.6
      def to_a
        ary = []
        each_packet_with_interface do |pkt, itf|
          ary << parse_packet(pkt.data.to_s, itf.link_type)
        end

        ary
      end

      # Translates a {File} into a hash with timestamps as keys.
      # @note Only packets from {EPB} sections are extracted, as {SPB} ones do not have timestamp.
      # @return [Hash{Time => Packet}]
      # @since 3.1.6
      def to_h
        hsh = {}
        each_packet_with_interface do |pkt, itf|
          next if pkt.is_a?(SPB)

          hsh[pkt.timestamp] = parse_packet(pkt.data.to_s, itf.link_type)
        end

        hsh
      end

      # Writes the {File} to a file.
      # @param [Hash] options
      # @option options [Boolean] :append (default: +false+) if set to +true+,
      #   the packets are appended to the file, rather than overwriting it
      # @return [Array] array of 2 elements: filename and size written
      # @todo for 4.0, replace +options+ by +append+ kwarg
      def to_file(filename, options={})
        mode = options[:append] && ::File.exist?(filename) ? 'ab' : 'wb'
        ::File.open(filename, mode) { |f| f.write(self.to_s) }
        [filename, self.to_s.size]
      end
      alias to_f to_file

      # Shorthand method for writing to a file.
      # @param [#to_s] filename
      # @return [Array] see return value from {#to_file}
      def write(filename='out.pcapng')
        self.to_file(filename.to_s, append: false)
      end

      # Shorthand method for appending to a file.
      # @param [#to_s] filename
      # @return [Array] see return value from {#to_file}
      def append(filename='out.pcapng')
        self.to_file(filename.to_s, append: true)
      end

      # Update current object from an array of packets
      # @param [Array<Packet>] packets
      # @param [Time, nil] timestamp initial timestamp, used for first packet
      # @param [Numeric, nil] ts_inc timestamp increment, in seconds, to increment
      #                       initial timestamp for each packet
      # @return [self]
      # @note if +timestamp+ and/or +ts_inc+ are nil, {SPB} sections are created
      #  for each packet, else {EPB} ones are used
      # @since 3.1.6
      def read_array(packets, timestamp: nil, ts_inc: nil)
        ts = timestamp
        section = create_new_shb_section
        packets.each do |pkt|
          block = create_block_from_pkt(pkt, section, ts, ts_inc)
          classify_block(section, block)
          ts = update_ts(ts, ts_inc)
        end
        self
      end

      # Update current object from a hash of packets and timestamps
      # @param [Hash{Time => Packet}] hsh
      # @return [self]
      # @since 3.1.6
      def read_hash(hsh)
        section = create_new_shb_section
        hsh.each do |ts, pkt|
          block = create_block_from_pkt(pkt, section, ts, 0)
          classify_block(section, block)
        end
        self
      end

      # @return [String]
      # @since 3.1.6
      def inspect
        str = +''
        sections.each do |section|
          str << section.inspect
          section.interfaces.each do |itf|
            str << itf.inspect
            itf.packets.each { |block| str << block.inspect }
          end
        end

        str
      end

      private

      # Parse a section. A section is made of at least a SHB. It than may contain
      # others blocks, such as IDB, SPB or EPB.
      # @param [IO] io
      # @return [void]
      def parse_section(io)
        shb = parse_shb(SHB.new, io)
        raise InvalidFileError, 'no Section header found' unless shb.is_a?(SHB)

        to_parse = if shb.section_len.to_i == 0xffffffffffffffff
                     # section length is undefined
                     io
                   else
                     # Section length is defined
                     StringIO.new(io.read(shb.section_len.to_i))
                   end

        until to_parse.eof?
          shb = @sections.last
          parse_shb shb, to_parse
        end
      end

      # Parse a SHB
      # @param [SHB] shb SHB to parse
      # @param [IO] io stream from which parse SHB
      # @return [SHB]
      def parse_shb(shb, io)
        type = BinStruct::Int32.new(value: 0, endian: shb.endian).read(io.read(4))
        io.seek(-4, IO::SEEK_CUR)
        parse(type, io, shb)
      end

      # Parse a block from its type
      # @param [BinStruct::Int32] type
      # @param [IO] io stream from which parse block
      # @param [SHB] shb header of current section
      # @return [Block]
      def parse(type, io, shb)
        block = guess_block_type(type).new(endian: shb.endian)
        classify_block shb, block
        block.read(io)
      end

      # Guess class to use from type
      # @param [BinStruct::Int] type
      # @return [Block]
      def guess_block_type(type)
        BLOCK_TYPES.key?(type.to_i) ? BLOCK_TYPES[type.to_i] : UnknownBlock
      end

      # Classify block from its type
      # @param [SHB] shb header of current section
      # @param [Block] block block to classify
      # @return [void]
      def classify_block(shb, block)
        case block
        when SHB
          @sections << block
        when IDB
          shb << block
        when SPB, EPB
          ifid = block.is_a?(EPB) ? block.interface_id : 0
          shb.interfaces[ifid] << block
        else
          shb.add_unknown_block(block)
        end
      end

      def create_new_shb_section
        section = SHB.new
        @sections << section
        itf = IDB.new(endian: section.endian)
        classify_block section, itf

        section
      end

      # Compute tsh and tsl from ts
      def calc_ts(timeslot, ts_resol)
        this_ts = (timeslot / ts_resol).to_i

        [this_ts >> 32, this_ts & 0xffffffff]
      end

      def reread(filename)
        return if filename.nil?

        clear
        readfile filename
      end

      def create_block_from_pkt(pkt, section, timestamp, ts_inc)
        if timestamp.nil? || ts_inc.nil?
          spb_from_pkt(pkt, section)
        else
          epb_from_pkt(pkt, section, timestamp)
        end
      end

      def spb_from_pkt(pkt, section)
        pkt_s = pkt.to_s
        size = pkt_s.size
        SPB.new(endian: section.endian,
                block_len: size,
                orig_len: size,
                data: pkt_s)
      end

      # @todo remove hash case when #array_to_file will be removed
      def epb_from_pkt(pkt, section, timestamp)
        this_ts, this_data = case pkt
                             when Hash
                               [pkt.keys.first.to_i, pkt.values.first.to_s]
                             else
                               [timestamp.to_r, pkt.to_s]
                             end
        this_cap_len = this_data.size
        this_tsh, this_tsl = calc_ts(this_ts, section.interfaces.last.ts_resol)
        EPB.new(endian: section.endian,
                interface_id: 0,
                tsh: this_tsh,
                tsl: this_tsl,
                cap_len: this_cap_len,
                orig_len: this_cap_len,
                data: this_data)
      end

      def update_ts(timestamp, ts_inc)
        return nil if timestamp.nil? || ts_inc.nil?

        timestamp + ts_inc
      end

      # Iterate over each xPB with its associated interface
      # @return [void]
      # @yieldparam [String] xpb
      # @yieldparam [IDB] itf
      def each_packet_with_interface
        sections.each do |section|
          section.interfaces.each do |itf|
            itf.packets.each { |xpb| yield xpb, itf }
          end
        end
      end

      def parse_packet(data, link_type)
        Packet.parse(data, first_header: KNOWN_LINK_TYPES[link_type])
      end
    end
  end
end
