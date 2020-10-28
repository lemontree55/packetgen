# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module PcapNG
    # PcapNG::File is a complete Pcap-NG file handler.
    # @author Sylvain Daubert
    class File
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
      BLOCK_TYPES = Hash[
        PcapNG.constants(false).select { |c| c.to_s.include?('_TYPE') }.map do |c|
          type_value = PcapNG.const_get(c).to_i
          klass = PcapNG.const_get(c.to_s[0..-6]) # TODO: use delete_suffix('_TYPE') when support for Ruby 2.4 will stop
          [type_value, klass]
        end
      ].freeze

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
        PacketGen.force_binary(str)
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

        ::File.open(fname, 'rb') do |f|
          parse_section(f) until f.eof?
        end

        return unless blk

        count = 0
        @sections.each do |section|
          section.interfaces.each do |intf|
            intf.packets.each do |pkt|
              count += 1
              yield pkt
            end
          end
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
          first_header = KNOWN_LINK_TYPES[link_type]
          parsed_pkt = Packet.parse(packet, first_header: first_header)
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

      # @deprecated
      #  Prefer use of {#to_a} or {#to_h}.
      # Translates a {File} into an array of packets.
      # @param [Hash] options
      # @option options [String] :file if given, object is cleared and filename
      #   is analyzed before generating array. Else, array is generated from +self+
      # @option options [Boolean] :keep_timestamps if +true+ (default value: +false+),
      #   generates an array of hashes, each one with timestamp as key and packet
      #   as value. There is one hash per packet.
      # @return [Array<Packet>,Array<Hash>]
      def file_to_array(options={})
        Deprecation.deprecated(self.class, __method__)

        file = options[:file] || options[:filename]
        reread file

        ary = []
        @sections.each do |section|
          section.interfaces.each do |itf|
            blk = if options[:keep_timestamps] || options[:keep_ts]
                    proc { |pkt| { pkt.timestamp => pkt.data.to_s } }
                  else
                    proc { |pkt| pkt.data.to_s }
                  end
            ary.concat(itf.packets.map(&blk))
          end
        end
        ary
      end

      # Translates a {File} into an array of packets.
      # @return [Array<Packet>]
      def to_a
        ary = []
        @sections.each do |section|
          section.interfaces.each do |itf|
            fh = KNOWN_LINK_TYPES[itf.link_type]
            ary.concat(itf.packets.map { |pkt| Packet.parse(pkt.data.to_s, first_header: fh) })
          end
        end

        ary
      end

      # Translates a {File} into a hash with timestamps as keys.
      # @return [Hash{Time => Packet}]
      def to_h
        hsh = {}
        @sections.each do |section|
          section.interfaces.each do |itf|
            fh = KNOWN_LINK_TYPES[itf.link_type]
            itf.packets.map do |pkt|
              hsh[pkt.timestamp] = Packet.parse(pkt.data.to_s, first_header: fh)
            end
          end
        end

        hsh
      end

      # Writes the {File} to a file.
      # @param [Hash] options
      # @option options [Boolean] :append (default: +false+) if set to +true+,
      #   the packets are appended to the file, rather than overwriting it
      # @return [Array] array of 2 elements: filename and size written
      def to_file(filename, options={})
        mode = if options[:append] && ::File.exist?(filename)
                 'ab'
               else
                 'wb'
               end
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

      # @overload array_to_file(ary)
      #  Update {File} object with packets.
      #  @param [Array] ary as generated by {#file_to_array} or Array of Packet objects.
      #                 Update {File} object without writing file on disk
      #  @return [self]
      # @overload array_to_file(options={})
      #  Update {File} and/or write it to a file
      #  @param [Hash] options
      #  @option options [String] :file file written on disk only if given
      #  @option options [Array] :array can either be an array of packet data,
      #                                 or a hash-value pair of timestamp => data.
      #  @option options [Time] :timestamp set an initial timestamp
      #  @option options [Integer] :ts_inc set the increment between timestamps.
      #                                    Defaults to 1
      #  @option options [Boolean] :append if +true+, append packets to the end of
      #                                    the file
      #  @return [Array] see return value from {#to_file}
      def array_to_file(options={})
        filename, ary, ts, ts_inc, append = array_to_file_options(options)

        section = create_new_shb_section
        ts_resol = section.interfaces.last.ts_resol

        ts_add_val = 0 # value to add to ts in Array case
        ary.each do |pkt|
          classify_block(section, epb_from_pkt(pkt, section.endian, ts, ts_resol, ts_add_val))
          ts_add_val += ts_inc
        end

        if filename
          self.to_f(filename, append: append)
        else
          self
        end
      end

      private

      # Parse a section. A section is made of at least a SHB. It than may contain
      # others blocks, such as IDB, SPB or EPB.
      # @param [IO] io
      # @return [void]
      def parse_section(io)
        shb = parse_shb(SHB.new, io)
        raise InvalidFileError, 'no Section header found' unless shb.is_a?(SHB)

        to_parse = if shb.section_len.to_i != 0xffffffffffffffff
                     # Section length is defined
                     StringIO.new(io.read(shb.section_len.to_i))
                   else
                     # section length is undefined
                     io
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
        type = Types::Int32.new(0, shb.endian).read(io.read(4))
        io.seek(-4, IO::SEEK_CUR)
        parse(type, io, shb)
      end

      # Parse a block from its type
      # @param [Types::Int32] type
      # @param [IO] io stream from which parse block
      # @param [SHB] shb header of current section
      # @return [Block]
      def parse(type, io, shb)
        block = guess_block_type(type).new(endian: shb.endian)
        classify_block shb, block
        block.read(io)
      end

      # Guess class to use from type
      # @param [Types::Int] type
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
          block.section = shb
        when SPB, EPB
          ifid = block.is_a?(EPB) ? block.interface_id : 0
          shb.interfaces[ifid] << block
          block.interface = shb.interfaces[ifid]
        else
          shb.unknown_blocks << block
          block.section = shb
        end
      end

      def array_to_file_options(options)
        case options
        when Hash
          array_to_file_options_from_hash(options)
        when Array
          [nil, options, Time.now, 1, false]
        else
          raise ArgumentError, 'unknown argument. Need either a Hash or Array'
        end
      end

      # Extract and check options for #array_to_file
      def array_to_file_options_from_hash(options)
        %i[filename arr ts].each do |deprecated_opt|
          Deprecation.deprecated_option(self.class, :array_to_file, deprecated_opt) if options[deprecated_opt]
        end

        filename = options[:filename] || options[:file]
        ary = options[:array] || options[:arr]
        raise ArgumentError, ':array parameter needs to be an array' unless ary.is_a? Array

        ts = options[:timestamp] || options[:ts] || Time.now
        ts_inc = options[:ts_inc] || 1
        append = !options[:append].nil?

        [filename, ary, ts, ts_inc, append]
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

      def epb_from_pkt(pkt, endian, ts, ts_resol, ts_add_val)
        this_ts, this_data = case pkt
                             when Hash
                               [pkt.keys.first.to_i, pkt.values.first.to_s]
                             else
                               [(ts + ts_add_val).to_i, pkt.to_s]
                             end
        this_cap_len = this_data.size
        this_tsh, this_tsl = calc_ts(this_ts, ts_resol)
        EPB.new(endian: endian,
                interface_id: 0,
                tsh: this_tsh,
                tsl: this_tsl,
                cap_len: this_cap_len,
                orig_len: this_cap_len,
                data: this_data)
      end
    end
  end
end
