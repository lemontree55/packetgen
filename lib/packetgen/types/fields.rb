# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types

    # @abstract Set of fields
    # This class is a base class to define headers or anything else with a binary
    # format containing multiple fields.
    #
    # == Basics
    # A {Fields} subclass is generaly composed of multiple binary fields. These fields
    # have each a given type. All types from {Types} module are supported, and all
    # {Fields} subclasses may also be used as field type.
    #
    # To define a new subclass, it has to inherit from {Fields}. And some class
    # methods have to be used to declare attributes/fields:
    #   class MyBinaryStructure < PacketGen::Types::Fields
    #     # define a first Int8 attribute, with default value: 1
    #     define_field :attr1, PacketGen::Types::Int8, default: 1
    #     #define a second attribute, of kind Int32
    #     define_field :attr2, PacketGen::Types::Int32
    #   end
    #
    # These defintions create 4 methods: +#attr1+, +#attr1=+, +#attr2+ and +#attr2=+.
    # All these methods take and/or return Integers.
    #
    # Fields may also be accessed through {#[]} ans {#[]=}. These methods give access
    # to type object:
    #   mybs = MyBinaryStructure.new
    #   mybs.attr1     # => Integer
    #   mybs[:attr1]   # => PacketGen::Types::Int8
    #
    # {#initialize} accepts an option hash to populate attributes. Keys are attribute
    # name symbols, and values are those expected by writer accessor.
    #
    # {#read} is able to populate object from a binary string.
    #
    # {#to_s} returns binary string from object.
    #
    # == Add Fields
    # {.define_field} adds a field to Fields subclass. A lot of field types may be
    # defined: integer types, string types (to handle a stream of bytes). More
    # complex field types may be defined using others Fields subclasses:
    #   # define a 16-bit little-endian integer field, named type
    #   define_field :type, PacketGen::Types::Int16le
    #   # define a string field
    #   define_field :body, PacketGen::Types::String
    #   # define afield using a complex type (Fields subclass)
    #   define_field :mac_addr, PacketGen::Eth::MacAddr
    #
    # This example creates six methods on our Fields subclass: +#type+, +#type=+,
    # +#body+, +#body=+, +#mac_addr+ and +#mac_addr=+.
    #
    # {.define_field} has many options (third optional Hash argument):
    # * +:default+ gives default field value. It may be a simple value (an Integer
    #   for an Int field, for example) or a lambda,
    # * +:builder+ to give a builder/constructor lambda to create field. The lambda
    #   takes one argument: {Fields} subclass object owning field.
    # For example:
    #   # 32-bit integer field defaulting to 1
    #   define_field :type, PacketGen::Types::Int32, default: 1
    #   # 16-bit integer field, created with a random value. Each instance of this
    #   # object will have a different value.
    #   define_field :id, PacketGen::Types::Int16, default: ->{ rand(65535) }
    #   # a size field
    #   define_field :body_size, PacketGen::Type::Int16
    #   # String field which length is taken from body_size field
    #   define_field :body, PacketGen::Type::String, builder: ->(obj) { PacketGen::Type::String.new('', length_from: obj[:body_size]) }
    #
    # {.define_field_before} and {.define_field_after} are also defined to relatively
    # create a field from anoher one (for example, when adding a field in a subclass).
    # == Generating bit fields
    # {.define_bit_fields_on} creates a bit field on a previuously declared integer
    # field. For example, +frag+ field in IP header:
    #   define_field :frag, Types::Int16, default: 0
    #   define_bit_fields_on :frag, :flag_rsv, :flag_df, :flag_mf, :fragment_offset, 13
    #
    # This example generates methods:
    # * +#frag+ and +#frag=+ to access +frag+ field as a 16-bit integer,
    # * +#flag_rsv?+, +#flag_rsv=+, +#flag_df?+, +#flag_df=+, +#flag_mf?+ and +#flag_mf=+
    #   to access Boolean RSV, MF and DF flags from +frag+ field,
    # * +#fragment_offset+ and +#fragment_offset=+ to access 13-bit integer fragment
    #   offset subfield from +frag+ field.
    # @author Sylvain Daubert
    class Fields

      # @private
      @ordered_fields = []
      # @private
      @field_defs = {}
      # @private
      @bit_fields = []

      # On inheritage, create +@field_defs+ class variable
      # @param [Class] klass
      # @return [void]
      def self.inherited(klass)
        ordered = @ordered_fields.clone
        field_defs = @field_defs.clone
        bf = @bit_fields.clone
        klass.class_eval do
          @ordered_fields = ordered
          @field_defs = field_defs
          @bit_fields = bf
        end
      end

      # Define a field in class
      #   class BinaryStruct < PacketGen::Types::Fields
      #     # 8-bit value
      #     define_field :value1, Types::Int8
      #     # 16-bit value
      #     define_field :value2, Types::Int16
      #     # specific class, may use a specific constructor
      #     define_field :value3, MyClass, builder: ->(obj) { Myclass.new(obj) }
      #   end
      #
      #   bs = BinaryStruct.new
      #   bs[value1]   # => Types::Int8
      #   bs.value1    # => Integer
      # @param [Symbol] name field name
      # @param [Object] type class or instance
      # @param [Hash] options Unrecognized options are passed to object builder if
      #   +:builder+ option is not set.
      # @option options [Object] :default default value
      # @option options [Lambda] :builder lambda to construct this field.
      #   Parameter to this lambda is the caller object.
      # @return [void]
      def self.define_field(name, type, options={})
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
        @field_defs[name] = [type, options.delete(:default), options.delete(:builder),
                             options]
        @ordered_fields << name
      end

      # Define a field, before another one
      # @param [Symbol,nil] other field name to create a new one before. If +nil+,
      #    new field is appended.
      # @param [Symbol] name field name to create
      # @param [Object] type class or instance
      # @param [Hash] options See {.define_field}.
      # @return [void]
      # @see .define_field
      def self.define_field_before(other, name, type, options={})
        define_field name, type, options
        unless other.nil?
          @ordered_fields.delete name
          idx = @ordered_fields.index(other)
          raise ArgumentError, "unknown #{other} field" if idx.nil?
          @ordered_fields[idx, 0] = name
        end
      end

      # Define a field, after another one
      # @param [Symbol,nil] other field name to create a new one after. If +nil+,
      #    new field is appended.
      # @param [Symbol] name field name to create
      # @param [Object] type class or instance
      # @param [Hash] options See {.define_field}.
      # @return [void]
      # @see .define_field
      def self.define_field_after(other, name, type, options={})
        define_field name, type, options
        unless other.nil?
          @ordered_fields.delete name
          idx = @ordered_fields.index(other)
          raise ArgumentError, "unknown #{other} field" if idx.nil?
          @ordered_fields[idx+1, 0] = name
        end
      end

      # Delete a previously defined field
      # @param [Symbol] name
      # @return [void]
      def self.delete_field(name)
        @ordered_fields.delete name
        @field_defs.delete name
      end

      # Define a bitfield on given attribute
      #   class MyHeader < PacketGen::Types::Fields
      #     define_field :flags, Types::Int16
      #     # define a bit field on :flag attribute:
      #     # flag1, flag2 and flag3 are 1-bit fields
      #     # type and stype are 3-bit fields. reserved is a 6-bit field
      #     define_bit_fields_on :flags, :flag1, :flag2, :flag3, :type, 3, :stype, 3, :reserved, 7
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
        attr_def = @field_defs[attr]
        raise ArgumentError, "unknown #{attr} field" if attr_def.nil?
        type = attr_def.first
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
      #   attributes, as defined by {.define_field} and by {.define_bit_fields_on}.
      def initialize(options={})
        @fields = {}
        self.class.class_eval { @field_defs }.each do |field, ary|
          default = ary[1].is_a?(Proc) ? ary[1].call : ary[1]
          @fields[field] = if ary[2]
                             ary[2].call(self)
                           elsif !ary[3].empty?
                             ary[0].new(ary[3])
                           else
                             ary[0].new
                           end

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
        @ordered_fields ||= self.class.class_eval { @ordered_fields }
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
        fields.each do |attr|
          next if attr == :body
          str << Inspect.inspect_attribute(attr, self[attr], 2)
        end
        str
      end

      # Return object as a binary string
      # @return [String]
      def to_s
        fields.map { |f| force_binary @fields[f].to_s }.join
      end

      # Size of object as binary string
      # @return [nteger]
      def sz
        to_s.size
      end

      # Return object as a hash
      # @return [Hash] keys: attributes, values: attribute values
      def to_h
        Hash[fields.map { |f| [f, @fields[f]] }]
      end

      # Used to set body as value of body object.
      # @param [String,Int,Fields,nil] value
      # @return [void]
      # @raise [BodyError] no body on given object
      # @raise [ArgumentError] cannot cram +body+ in +:body+ field
      def body=(value)
        raise BodyError, 'no body field'  unless @fields.has_key? :body
        case body
        when ::String
          self[:body].read value
        when Int, Fields
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
