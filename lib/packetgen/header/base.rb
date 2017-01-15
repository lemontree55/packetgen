module PacketGen
  module Header

    # Base class for all header types
    # @author Sylvain Daubert
    class Base

      # @api private
      # Reference on packet which owns this header
      attr_accessor :packet

      def self.inherited(klass)
        klass.instance_eval { @fields = {}; @known_headers = {} }
      end

      # Bind a upper header to current class
      # @param [Class] header_klass header class to bind to current class
      # @param [Hash] args current class fields and their value when +header_klass+
      #  is embedded in current class
      # @return [void]
      def self.bind_header(header_klass, args={})
        @known_headers[header_klass] ||= []
        args.each do |key, value|
          @known_headers[header_klass] << Binding.new(key, value)
        end
      end

      # @api private
      # Get knwon headers
      # @return [Hash] keys: header classes, values: array of {Binding}
      def self.known_headers
        @known_headers
      end


      # Define a field in a Struct subclass
      # @param [Symbol] name field name
      # @param [StructFu] type type from StructFu module
      # @param [Object] default default value
      # @return [void]
      def self.define_field(name, type, default=nil)
        if type < StructFu::Int
          class_eval "def #{name}; self[:#{name}].to_i; end\n" \
                     "def #{name}=(val) self[:#{name}].read val; end"
        else
          class_eval "def #{name}; self[:#{name}]; end\n" \
                          "def #{name}=(val) self[:#{name}].read val; end"
        end

        @fields[name] = [type, default]
      end

      # Define a bitfield on given attribute
      #   class MyHeader < Struct.new(:flags)
      #   
      #     def initialize(options={})
      #       super Int16.new(options[:flags])
      #     end
      #     
      #     # define a bit field on :flag attribute:
      #     # flag1, flag2 and flag3 are 1-bit fields
      #     # type and stype are 3-bit fields. reserved is a 6-bit field
      #     define_bit_fields_on :flags, :flag1, :flag2, :flag3, :type, 3, :stype, 3, :reserved: 6
      #   end
      # A bitfield of size 1 bit defines 2 methods:
      # * +#field?+ which returns a Boolean,
      # * +#field=+ which takes and returns a Boolean.
      # A bitfield of more bits defines 2 methods:
      # * +#field+ which returns an Integer,
      # * +#field=+ which takes and returns an Integer.
      # @param [Symbol] attr attribute name (attribute should a {StructFu::Int}
      #   subclass)
      # @param [Array] args list of bitfield names. Name may be followed
      #   by bitfield size. If no size is given, 1 bit is assumed.
      # @return [void]
      def self.define_bit_fields_on(attr, *args)
        total_size = self.new[attr].width * 8
        idx = total_size - 1

        field = args.shift
        while field
          next unless field.is_a? Symbol
          size = if args.first.is_a? Integer
                   args.shift
                 else
                   1
                 end
          unless field == :_
            shift = idx - (size - 1)
            field_mask = (2**size - 1) << shift
            clear_mask = (2**total_size - 1) & (~field_mask & (2**total_size - 1))

            if size == 1
              class_eval <<-EOM
              def #{field}?
                val = (self[:#{attr}].to_i & #{field_mask}) >> #{shift}
                val != 0
              end
              def #{field}=(v)
                val = v ? 1 : 0
                self[:#{attr}].value = self[:#{attr}].to_i & #{clear_mask}
                self[:#{attr}].value |= val << #{shift}
              end
              EOM
            else
              class_eval <<-EOM
              def #{field}
                (self[:#{attr}].to_i & #{field_mask}) >> #{shift}
              end
              def #{field}=(v)
                self[:#{attr}].value = self[:#{attr}].to_i & #{clear_mask}
                self[:#{attr}].value |= (v & #{2**size - 1}) << #{shift}
              end
              EOM
            end
          end

          idx -= size
          field = args.shift
        end
      end

      # Create a new header object
      # @param [Hash] options
      def initialize(options={})
        @fields = {}
        self.class.class_eval { @fields }.each do |field, ary|
          @fields[field] = ary[0].new(options[field] || ary[1])
        end
      end

      # Get field object
      # @param [Symbol] field
      # @return [Object]
      def [](field)
        @fields[field]
      end

      # Set field object
      # @param [Symbol] field
      # @param [Object] obj
      # @return [Object]
      def []=(field, obj)
        @fields[field] = obj
      end

      def fields
        @fields.keys
      end

      # @api private
      # Get +header+ id in packet headers array
      # @param [Header] header
      # @return [Integer]
      # @raise FormatError +header+ not in a packet
      def header_id(header)
        raise FormatError, "header of type #{header.class} not in a packet" if packet.nil?
        id = packet.headers.index(header)
        if id.nil?
          raise FormatError, "header of type #{header.class} not in packet #{packet}"
        end
        id
      end

      # @api private
      # Get IP or IPv6 previous header from +header+
      # @param [Header] header
      # @return [Header]
      # @raise FormatError no IP or IPv6 header previous +header+ in packet
      # @raise FormatError +header+ not in a packet
      def ip_header(header)
        hid = header_id(header)
        iph = packet.headers[0...hid].reverse.find { |h| h.is_a? IP or h.is_a? IPv6 }
        raise FormatError, 'no IP or IPv6 header in packet' if iph.nil?
        iph
      end

      # Return header protocol name
      # @return [String]
      def protocol_name
        self.class.to_s.sub(/.*::/, '')
      end

      # Common inspect method for headers
      # @return [String]
      def inspect
        str = Inspect.dashed_line(self.class, 2)
        @fields.each do |attr, value|
          next if attr == :body
          str << Inspect.inspect_attribute(attr, value, 2)
        end
        str
      end

      def to_s
        @fields.values.map { |v| v.to_s }.join
      end

      def sz
        to_s.size
      end

      def force_binary(str)
        PacketGen.force_binary(str)
      end
    end
  end
end
