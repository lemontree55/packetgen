# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types

    # @abstract
    # Set of fields
    # @author Sylvain Daubert
    class Fields

      # @private
      @field_defs = {}
      # @private
      @bit_fields = []

      # On inheritage, create +@field_defs+ class variable
      # @param [Class] klass
      # @return [void]
      def self.inherited(klass)
        field_defs = @field_defs.clone
        bf = @bit_fields.clone
        klass.class_eval { @field_defs = field_defs; @bit_fields = bf }
      end

      # Define a field in
      #   class BinaryStruct < PacketGen::Types::Fields
      #     # 8-bit value
      #     define_field :value1, Types::Int8
      #     # 16-bit value
      #     define_field :value2, Types::Int16
      #     # specific class, may use a specific constructor
      #     define_field :value3, MyClass, constructor: ->(obj) { Myclass.new(obj) }
      #   end
      #
      #   bs = BinaryStruct.new
      #   bs[value1]   # => Types::Int8
      #   bs.value1    # => Integer
      # @param [Symbol] name field name
      # @param [Object] type class or instance
      # @param [Object] default default value
      # @param [Lambda] builder lambda to construct this field. Parameter to this
      #   lambda is the caller object.
      # @return [void]
      def self.define_field(name, type, default: nil, builder: nil)
        define = []
        if type < Types::Int
          define << "def #{name}; self[:#{name}].to_i; end"
          define << "def #{name}=(val) self[:#{name}].read val; end"
        elsif type.instance_methods.include? :to_human and
             type.instance_methods.include? :from_human
          define << "def #{name}; self[:#{name}].to_human; end"
          define << "def #{name}=(val) self[:#{name}].from_human val; end"
        else
          define << "def #{name}; self[:#{name}]; end\n"
          define << "def #{name}=(val) self[:#{name}].read val; end"
        end

        define.delete(1) if type.instance_methods.include? "#{name}=".to_sym
        define.delete(0) if type.instance_methods.include? name
        class_eval define.join("\n")

        @field_defs[name] = [type, default, builder]
      end

      # Define a bitfield on given attribute
      #   class MyHeader < PacketGen::Types::Fields
      #     define_field :flags, Types::Int16
      #     # define a bit field on :flag attribute:
      #     # flag1, flag2 and flag3 are 1-bit fields
      #     # type and stype are 3-bit fields. reserved is a 6-bit field
      #     define_bit_fields_on :flags, :flag1, :flag2, :flag3, :type, 3, :stype, 3, :reserved: 7
      #   end
      # A bitfield of size 1 bit defines 2 methods:
      # * +#field?+ which returns a Boolean,
      # * +#field=+ which takes and returns a Boolean.
      # A bitfield of more bits defines 2 methods:
      # * +#field+ which returns an Integer,
      # * +#field=+ which takes and returns an Integer.
      # @param [Symbol] attr attribute name (attribute should be a {Types::Int}
      #   subclass)
      # @param [Array] args list of bitfield names. Name may be followed
      #   by bitfield size. If no size is given, 1 bit is assumed.
      # @return [void]
      def self.define_bit_fields_on(attr, *args)
        type = @field_defs[attr].first
        unless type < Types::Int
          raise TypeError, "#{attr} is not a PacketGen::Types::Int"
        end
        total_size = type.new.width * 8
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

            @bit_fields << field
          end

          idx -= size
          field = args.shift
        end
      end

      # Create a new header object
      # @param [Hash] options Keys are symbols. They should have name of object
      #   attributes, as defined by {.define_field} and by {.define_bit_field}.
      def initialize(options={})
        @fields = {}
        self.class.class_eval { @field_defs }.each do |field, ary|
          default = ary[1].is_a?(Proc) ? ary[1].call : ary[1]
          @fields[field] = ary[2] ? ary[2].call(self) : ary[0].new

          value = options[field] || default
          if ary[0] < Types::Int
            @fields[field].read(value)
          elsif ary[0] <= Types::String
            @fields[field].read(value)
          else
            @fields[field].from_human(value) if @fields[field].respond_to? :from_human
          end
        end
        self.class.class_eval { @bit_fields }.each do |bit_field|
          self.send "#{bit_field}=", options[bit_field] if options[bit_field]
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

      # Populate object from a binary string
      # @param [String] str
      # @return [Fields] self
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

      # Return object as a binary string
      # @return [String]
      def to_s
        @fields.values.map { |v| force_binary v.to_s }.join
      end

      # Size of object as binary strinf
      # @return [nteger]
      def sz
        to_s.size
      end

      # Return object as a hash
      # @return [Hash] keys: attributes, values: attribute values
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
        when Types::Int, Base
          self[:body] = value
        when NilClass
          self[:body] = Types::String.new.read('')
        else
          raise ArgumentError, "Can't cram a #{body.class} in a :body field"
        end
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
