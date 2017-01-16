module PacketGen
  module Header

    # Base class for all header types
    # @author Sylvain Daubert
    class Base

      # @api private
      # Simple class to handle header association
      Binding = Struct.new(:key, :value)

      # @api private
      # Reference on packet which owns this header
      attr_accessor :packet

      # @private
      @field_defs = {}

      def self.inherited(klass)
        field_defs = @field_defs.clone
        klass.class_eval { @field_defs = field_defs; @known_headers = {} }
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
      # @param [Object] type class or instance
      # @param [Object] default default value
      # @return [void]
      def self.define_field(name, type, default=nil)
        type_inst = type.is_a?(Class) ? type.new : type

        define = []
        if type_inst.is_a?(StructFu::Int)
          define << "def #{name}; self[:#{name}].to_i; end"
          define << "def #{name}=(val) self[:#{name}].read val; end"
        elsif type_inst.respond_to? :to_human
          define << "def #{name}; self[:#{name}].to_human; end"
          define << "def #{name}=(val) self[:#{name}].from_human val; end"
        else
          define << "def #{name}; self[:#{name}]; end\n"
          define << "def #{name}=(val) self[:#{name}].read val; end"
        end

        define.delete(1) if type_inst.respond_to? "#{name}="
        define.delete(0) if type_inst.respond_to? name
        class_eval define.join("\n")

        @field_defs[name] = [type, default]
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
        self.class.class_eval { @field_defs }.each do |field, ary|
          default = ary[1].is_a?(Proc) ? ary[1].call : ary[1]
          if ary[0].is_a?(Class)
            if ary[0] < StructFu::Int
              @fields[field] = ary[0].new(options[field] || default)
            elsif ary[0] <= StructFu::String
              @fields[field] = ary[0].new
              @fields[field].read(options[field] || default)
            else
              f = ary[0].new
              f.from_human(options[field] || default) if f.respond_to? :from_human
              @fields[field] = f
            end
          else
            case ary[0]
            when StructFu::Int
              @fields[field] = ary[0].read(options[field] || default)
            when StructFu::String
              @fields[field] = ary[0].read(options[field] || default)
            else
              f = ary[0]
              f.from_human(options[field] || default) if f.respond_to? :from_human
              @fields[field] = f
            end
          end
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

      # Get all field names
      # @return [Array<Symbol>]
      def fields
        @fields.keys
      end

      # Return header protocol name
      # @return [String]
      def protocol_name
        self.class.to_s.sub(/.*::/, '')
      end

      def read(str)
        return self if str.nil?
        force_binary str
        start = 0
        fields.each do |field|
          if self[field].respond_to? :width
            width = self[field].width
            self[field].read str[start, width]
            start += width
          elsif self[field].respond_to? :sz
            self[field].read str[start..-1]
            size = self[field].sz
            start += size
          else
            self[field].read str[start..-1]
            start = str.size
          end
        end

        self
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
        @fields.values.map { |v| force_binary v.to_s }.join
      end

      def sz
        to_s.size
      end

      def to_h
        @fields
      end

      # Used to set body as balue of body object.
      # @param [Object] value
      # @return [void]
      # @raise [BodyError] no body on given object
      # @raise [ArgumentError] cannot cram +body+ in +:body+ field
      def body=(value)
        raise BodyError, 'no body field'  unless @fields.has_key? :body
        case body
        when ::String
          self[:body].read value
        when StructFu::Int, Base
          self[:body] = value
        when NilClass
          self[:body] = StructFu::String.new.read('')
        else
          raise ArgumentError, "Can't cram a #{body.class} in a :body field"
        end
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

      # Force str to binary encoding
      # @param [String] str
      # @return [String]
      def force_binary(str)
        PacketGen.force_binary(str)
      end
    end
  end
end
