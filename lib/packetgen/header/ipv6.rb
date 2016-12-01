require 'ipaddr'

module PacketGen
  module Header

    # IPv6 header class
    # @author Sylvain Daubert
    class IPv6 < Struct.new(:version, :traffic_class, :flow_label, :length,
                            :next, :hop, :src, :dst, :body)
      include StructFu
      include HeaderMethods
      extend HeaderClassMethods

      # IPv6 address, as a group of 8 2-byte words
      # @author Sylvain Daubert
      class Addr < Struct.new(:a1, :a2, :a3, :a4, :a5, :a6, :a7, :a8)
        include StructFu

        # @param [Hash] options
        # @option options [Integer] :a1
        # @option options [Integer] :a2
        # @option options [Integer] :a3
        # @option options [Integer] :a4
        # @option options [Integer] :a5
        # @option options [Integer] :a6
        # @option options [Integer] :a7
        # @option options [Integer] :a8
        def initialize(options={})
          super Int16.new(options[:a1]),
                Int16.new(options[:a2]),
                Int16.new(options[:a3]),
                Int16.new(options[:a4]),
                Int16.new(options[:a5]),
                Int16.new(options[:a6]),
                Int16.new(options[:a7]),
                Int16.new(options[:a8])
        end

        # Parse a colon-delimited address
        # @param [String] str
        # @return [self]
        def parse(str)
          return self if str.nil?
          addr = IPAddr.new(str)
          raise ArgumentError, 'string is not a IPv6 address' unless addr.ipv6?
          addri = addr.to_i
          self.a1 = addri >> 112
          self.a2 = addri >> 96 & 0xffff
          self.a3 = addri >> 80 & 0xffff
          self.a4 = addri >> 64 & 0xffff
          self.a5 = addri >> 48 & 0xffff
          self.a6 = addri >> 32 & 0xffff
          self.a7 = addri >> 16 & 0xffff
          self.a8 = addri & 0xffff
          self
        end

        # Read a Addr6 from a binary string
        # @param [String] str
        # @return [self]
        def read(str)
          force_binary str
          self[:a1].read str[0, 2]
          self[:a2].read str[2, 2]
          self[:a3].read str[4, 2]
          self[:a4].read str[6, 2]
          self[:a5].read str[8, 2]
          self[:a6].read str[10, 2]
          self[:a7].read str[12, 2]
          self[:a8].read str[14, 2]
          self
        end

        %i(a1 a2 a3 a4 a5 a6 a7 a8).each do |sym|
          class_eval "def #{sym}; self[:#{sym}].to_i; end\n" \
                     "def #{sym}=(v); self[:#{sym}].read v; end" 
        end

        # Addr6 in human readable form (colon-delimited hex string)
        # @return [String]
        def to_x
          IPAddr.new(to_a.map { |a| a.to_i.to_s(16) }.join(':')).to_s
        end
      end

    end
  end
end
