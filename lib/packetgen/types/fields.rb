# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# rubocop:disable Metrics/ClassLength

module PacketGen
  module Types
    # @abstract Set of fields
    # This class is a base class to define headers or anything else with a binary
    # format containing multiple fields.
    #
    # == Basics
    # A {Fields} subclass is generaly composed of multiple binary fields. These fields
    # have each a given type. All {Fieldable} types are supported.
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
    #   # define a field using a complex type (Fields subclass)
    #   define_field :mac_addr, PacketGen::Eth::MacAddr
    #
    # This example creates six methods on our Fields subclass: +#type+, +#type=+,
    # +#body+, +#body=+, +#mac_addr+ and +#mac_addr=+.
    #
    # {.define_field} has many options (third optional Hash argument):
    # * +:default+ gives default field value. It may be a simple value (an Integer
    #   for an Int field, for example) or a lambda,
    # * +:builder+ to give a builder/constructor lambda to create field. The lambda
    #   takes 2 argument: {Fields} subclass object owning field, and type class as passes
    #   as second argument to .define_field,
    # * +:optional+ to define this field as optional. This option takes a lambda
    #   parameter used to say if this field is present or not. The lambda takes an argument
    #   ({Fields} subclass object owning field),
    # * +:enum+ to define Hash enumeration for an {Enum} type.
    # For example:
    #   # 32-bit integer field defaulting to 1
    #   define_field :type, PacketGen::Types::Int32, default: 1
    #   # 16-bit integer field, created with a random value. Each instance of this
    #   # object will have a different value.
    #   define_field :id, PacketGen::Types::Int16, default: ->(obj) { rand(65535) }
    #   # a size field
    #   define_field :body_size, PacketGen::Types::Int16
    #   # String field which length is taken from body_size field
    #   define_field :body, PacketGen::Types::String, builder: ->(obj, type) { type.new(length_from: obj[:body_size]) }
    #   # 16-bit enumeration type. As :default not specified, default to first value of enum
    #   define_field :type_class, PacketGen::Types::Int16Enum, enum: { 'class1' => 1, 'class2' => 2}
    #   # optional field. Only present if another field has a certain value
    #   define_field :opt1, PacketGen::Types::Int16, optional: ->(h) { h.type == 42 }
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
    #
    # == Creating a new field class from another one
    # Some methods may help in this case:
    # * {.define_field_before} to define a new field before an existing one,
    # * {.define_field_after} to define a new field after an existing onr,
    # * {.remove_field} to remove an existing field,
    # * {.uptade_fied} to change options of a field (but not its type),
    # * {.remove_bit_fields_on} to remove a bit fields definition.
    #
    # @author Sylvain Daubert
    class Fields
      # @private
      FieldDef = Struct.new(:type, :default, :builder, :optional, :enum, :options)
      # @private field names, ordered as they were declared
      @ordered_fields = []
      # @private field definitions
      @field_defs = {}
      # @private bit field definitions
      @bit_fields = {}

      class <<self
        # Get field definitions for this class.
        # @return [Hash]
        # @since 3.1.0
        attr_reader :field_defs
        # Get bit fields defintions for this class
        # @return [Hash]
        # @since 3.1.5
        attr_reader :bit_fields

        # On inheritage, create +@field_defs+ class variable
        # @param [Class] klass
        # @return [void]
        def inherited(klass)
          super

          field_defs = {}
          @field_defs.each do |k, v|
            field_defs[k] = v.clone
          end
          ordered = @ordered_fields.clone
          bf = bit_fields.clone

          klass.class_eval do
            @ordered_fields = ordered
            @field_defs = field_defs
            @bit_fields = bf
          end
        end

        # Get field names
        # @return [Array<Symbol>]
        def fields
          @ordered_fields
        end

        # Define a field in class
        #   class BinaryStruct < PacketGen::Types::Fields
        #     # 8-bit value
        #     define_field :value1, Types::Int8
        #     # 16-bit value
        #     define_field :value2, Types::Int16
        #     # specific class, may use a specific constructor
        #     define_field :value3, MyClass, builder: ->(obj, type) { type.new(obj) }
        #   end
        #
        #   bs = BinaryStruct.new
        #   bs[value1]   # => Types::Int8
        #   bs.value1    # => Integer
        # @param [Symbol] name field name
        # @param [Fieldable] type class or instance
        # @param [Hash] options Unrecognized options are passed to object builder if
        #   +:builder+ option is not set.
        # @option options [Object] :default default value. May be a proc. This lambda
        #   take one argument: the caller object.
        # @option options [Lambda] :builder lambda to construct this field.
        #   Parameters to this lambda is the caller object and the field type class.
        # @option options [Lambda] :optional define this field as optional. Given lambda
        #   is used to known if this field is present or not. Parameter to this lambda is
        #   the being defined Field object.
        # @option options [Hash] :enum mandatory option for an {Enum} type.
        #   Define enumeration: hash's keys are +String+, and values are +Integer+.
        # @return [void]
        def define_field(name, type, options={})
          fields << name
          field_defs[name] = FieldDef.new(type,
                                          options.delete(:default),
                                          options.delete(:builder),
                                          options.delete(:optional),
                                          options.delete(:enum),
                                          options)

          add_methods(name, type)
        end

        # Define a field, before another one
        # @param [Symbol,nil] other field name to create a new one before. If +nil+,
        #    new field is appended.
        # @param [Symbol] name field name to create
        # @param [Fieldable] type class or instance
        # @param [Hash] options See {.define_field}.
        # @return [void]
        # @see .define_field
        def define_field_before(other, name, type, options={})
          define_field name, type, options
          return if other.nil?

          fields.delete name
          idx = fields.index(other)
          raise ArgumentError, "unknown #{other} field" if idx.nil?

          fields[idx, 0] = name
        end

        # Define a field, after another one
        # @param [Symbol,nil] other field name to create a new one after. If +nil+,
        #    new field is appended.
        # @param [Symbol] name field name to create
        # @param [Fieldable] type class or instance
        # @param [Hash] options See {.define_field}.
        # @return [void]
        # @see .define_field
        def define_field_after(other, name, type, options={})
          define_field name, type, options
          return if other.nil?

          fields.delete name
          idx = fields.index(other)
          raise ArgumentError, "unknown #{other} field" if idx.nil?

          fields[idx + 1, 0] = name
        end

        # Remove a previously defined field
        # @param [Symbol] name
        # @return [void]
        # @since 2.8.4
        def remove_field(name)
          fields.delete name
          @field_defs.delete name
          undef_method name if method_defined?(name)
          undef_method "#{name}=" if method_defined?("#{name}=")
        end

        # Update a previously defined field
        # @param [Symbol] field field name to create
        # @param [Hash] options See {.define_field}.
        # @return [void]
        # @see .define_field
        # @raise [ArgumentError] unknown +field+
        # @since 2.8.4
        def update_field(field, options)
          check_existence_of field

          %i[default builder optional enum].each do |property|
            field_defs_property_from(field, property, options)
          end

          field_defs[field].options.merge!(options)
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
        # @raise [ArgumentError] unknown +attr+
        # @return [void]
        def define_bit_fields_on(attr, *args)
          check_existence_of attr

          type = field_defs[attr].type
          raise TypeError, "#{attr} is not a PacketGen::Types::Int" unless type < Types::Int

          total_size = type.new.nbits
          idx = total_size - 1

          until args.empty?
            field = args.shift
            next unless field.is_a? Symbol

            size = size_from(args)

            unless field == :_
              add_bit_methods(attr, field, size, total_size, idx)
              register_bit_field_size(attr, field, size)
            end

            idx -= size
          end
        end

        # Remove all bit fields defined on +attr+
        # @param [Symbol] attr attribute defining bit fields
        # @return [void]
        # @since 2.8.4
        def remove_bit_fields_on(attr)
          fields = bit_fields.delete(attr)
          return if fields.nil?

          fields.each do |field, size|
            undef_method "#{field}="
            undef_method(size == 1 ? "#{field}?" : field)
          end
        end

        private

        def add_methods(name, type)
          define = []
          if type < Types::Enum
            define << "def #{name}; self[:#{name}].to_i; end"
            define << "def #{name}=(val) self[:#{name}].value = val; end"
          else
            define << "def #{name}\n" \
                      "  to_and_from_human?(:#{name}) ? self[:#{name}].to_human : self[:#{name}]\n" \
                      'end'
            define << "def #{name}=(val)\n" \
                      "  to_and_from_human?(:#{name}) ? self[:#{name}].from_human(val) : self[:#{name}].read(val)\n" \
                      'end'
          end

          define.delete_at(1) if instance_methods.include? "#{name}=".to_sym
          define.delete_at(0) if instance_methods.include? name
          class_eval define.join("\n")
        end

        def add_bit_methods(attr, name, size, total_size, idx)
          shift = idx - (size - 1)

          if size == 1
            add_single_bit_methods(attr, name, size, total_size, shift)
          else
            add_multibit_methods(attr, name, size, total_size, shift)
          end
        end

        def compute_field_mask(size, shift)
          (2**size - 1) << shift
        end

        def compute_clear_mask(total_size, field_mask)
          (2**total_size - 1) & (~field_mask & (2**total_size - 1))
        end

        def add_single_bit_methods(attr, name, size, total_size, shift)
          field_mask = compute_field_mask(size, shift)
          clear_mask = compute_clear_mask(total_size, field_mask)

          class_eval <<-METHODS
          def #{name}?                                                  # def bit?
            val = (self[:#{attr}].to_i & #{field_mask}) >> #{shift}     #   val = (self[:attr}].to_i & 1}) >> 1
            val != 0                                                    #   val != 0
          end                                                           # end
          def #{name}=(v)                                               # def bit=(v)
            val = v ? 1 : 0                                             #   val = v ? 1 : 0
            self[:#{attr}].value = self[:#{attr}].to_i & #{clear_mask}  #   self[:attr].value = self[:attr].to_i & 0xfffd
            self[:#{attr}].value |= val << #{shift}                     #   self[:attr].value |= val << 1
          end                                                           # end
          METHODS
        end

        def add_multibit_methods(attr, name, size, total_size, shift)
          field_mask = compute_field_mask(size, shift)
          clear_mask = compute_clear_mask(total_size, field_mask)

          class_eval <<-METHODS
          def #{name}                                                   # def multibit
            (self[:#{attr}].to_i & #{field_mask}) >> #{shift}           #   (self[:attr].to_i & 6) >> 1
          end                                                           # end
          def #{name}=(v)                                               # def multibit=(v)
            self[:#{attr}].value = self[:#{attr}].to_i & #{clear_mask}  #   self[:attr].value = self[:attr].to_i & 0xfff9
            self[:#{attr}].value |= (v & #{2**size - 1}) << #{shift}    #   self[:attr].value |= (v & 3) << 1
          end                                                           # end
          METHODS
        end

        def register_bit_field_size(attr, field, size)
          bit_fields[attr] = {} if bit_fields[attr].nil?
          bit_fields[attr][field] = size
        end

        def field_defs_property_from(field, property, options)
          field_defs[field].send("#{property}=", options.delete(property)) if options.key?(property)
        end

        def size_from(args)
          if args.first.is_a? Integer
            args.shift
          else
            1
          end
        end

        def check_existence_of(field)
          raise ArgumentError, "unknown #{field} field for #{self}" unless field_defs.key?(field)
        end
      end

      # Create a new fields object
      # @param [Hash] options Keys are symbols. They should have name of object
      #   attributes, as defined by {.define_field} and by {.define_bit_fields_on}.
      def initialize(options={})
        @fields = {}
        @optional_fields = {}

        self.class.fields.each do |field|
          build_field field
          initialize_value field, options[field]
          initialize_optional field
        end

        self.class.bit_fields.each do |_, hsh|
          hsh.each_key do |bit_field|
            self.send "#{bit_field}=", options[bit_field] if options[bit_field]
          end
        end
      end

      # Get field object
      # @param [Symbol] field
      # @return [Fieldable]
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
        self.class.fields
      end

      # Get all optional field name
      # @return[Array<Symbol>,nil]
      def optional_fields
        @optional_fields.keys
      end

      # Say if this field is optional
      # @return [Boolean]
      def optional?(field)
        @optional_fields.key? field
      end

      # Say if an optional field is present
      # @return [Boolean]
      def present?(field)
        return true unless optional?(field)

        @optional_fields[field].call(self)
      end

      # Populate object from a binary string
      # @param [String] str
      # @return [Fields] self
      def read(str)
        return self if str.nil?

        force_binary str
        start = 0
        fields.each do |field|
          next unless present?(field)

          obj = self[field].read str[start..-1]
          start += self[field].sz
          self[field] = obj unless obj == self[field]
        end

        self
      end

      # Common inspect method for headers.
      #
      # A block may be given to differently format some attributes. This
      # may be used by subclasses to handle specific fields.
      # @yieldparam attr [Symbol] attribute to inspect
      # @yieldreturn [String,nil] the string to print for +attr+, or +nil+
      #  to let +inspect+ generate it
      # @return [String]
      def inspect
        str = Inspect.dashed_line(self.class, 1)
        fields.each do |attr|
          next if attr == :body
          next unless present?(attr)

          result = yield(attr) if block_given?
          str << (result || Inspect.inspect_attribute(attr, self[attr], 1))
        end
        str
      end

      # Return object as a binary string
      # @return [String]
      def to_s
        fields.select { |f| present?(f) }
              .map! { |f| force_binary @fields[f].to_s }.join
      end

      # Size of object as binary string
      # @return [nteger]
      def sz
        to_s.size
      end

      # Return object as a hash
      # @return [Hash] keys: attributes, values: attribute values
      def to_h
        fields.map { |f| [f, @fields[f].to_human] }.to_h
      end

      # Get offset of given field in {Fields} structure.
      # @param [Symbol] field
      # @return [Integer]
      # @raise [ArgumentError] unknown field
      def offset_of(field)
        raise ArgumentError, "#{field} is an unknown field of #{self.class}" unless @fields.include?(field)

        offset = 0
        fields.each do |f|
          break offset if f == field
          next unless present?(f)

          offset += self[f].sz
        end
      end

      # Get bit fields definition for given field.
      # @param [Symbol] field defining bit fields
      # @return [Hash,nil] keys: bit fields, values: their size in bits
      # @since 2.8.3
      def bits_on(field)
        self.class.bit_fields[field]
      end

      private

      # Deeply duplicate +@fields+
      # @return [void]
      def initialize_copy(_other)
        fields = {}
        @fields.each { |k, v| fields[k] = v.dup }
        @fields = fields
      end

      # Force str to binary encoding
      # @param [String] str
      # @return [String]
      def force_binary(str)
        PacketGen.force_binary(str)
      end

      # @param [Symbol] attr attribute
      # @return [Boolean] +tru+e if #from_human and #to_human are both defined for given attribute
      def to_and_from_human?(attr)
        self[attr].respond_to?(:to_human) && self[attr].respond_to?(:from_human)
      end

      def field_defs
        self.class.field_defs
      end

      # rubocop:disable Metrics/AbcSize
      def build_field(field)
        type = field_defs[field].type

        @fields[field] = if field_defs[field].builder
                           field_defs[field].builder.call(self, type)
                         elsif field_defs[field].enum
                           type.new(field_defs[field].enum)
                         elsif !field_defs[field].options.empty?
                           type.new(field_defs[field].options)
                         else
                           type.new
                         end
      end
      # rubocop:enable Metrics/AbcSize

      def initialize_value(field, val)
        type = field_defs[field].type
        default = field_defs[field].default
        default = default.to_proc.call(self) if default.is_a?(Proc)

        value = val || default
        if value.class <= type
          @fields[field] = value
        elsif @fields[field].respond_to? :from_human
          @fields[field].from_human(value)
        else
          @fields[field].read(value)
        end
      end

      def initialize_optional(field)
        optional = field_defs[field].optional
        @optional_fields[field] = optional if optional
      end
    end
  end
end

# rubocop:enable Metrics/ClassLength
