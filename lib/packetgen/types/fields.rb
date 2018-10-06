# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

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
    #   takes one argument: {Fields} subclass object owning field,
    # * +:optional+ to define this field as optional. This option takes a lambda
    #   parameter used to say if this field is present or not,
    # * +:enum+ to define Hash enumeration for an {Enum} type.
    # For example:
    #   # 32-bit integer field defaulting to 1
    #   define_field :type, PacketGen::Types::Int32, default: 1
    #   # 16-bit integer field, created with a random value. Each instance of this
    #   # object will have a different value.
    #   define_field :id, PacketGen::Types::Int16, default: ->{ rand(65535) }
    #   # a size field
    #   define_field :body_size, PacketGen::Types::Int16
    #   # String field which length is taken from body_size field
    #   define_field :body, PacketGen::Types::String, builder: ->(obj, type) { type.new('', length_from: obj[:body_size]) }
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
    # @author Sylvain Daubert
    class Fields
      # @private field names, ordered as they were declared
      @ordered_fields = []
      # @private field definitions
      @field_defs = {}
      # @private bit field definitions
      @bit_fields = {}

      class <<self
        # On inheritage, create +@field_defs+ class variable
        # @param [Class] klass
        # @return [void]
        def inherited(klass)
          field_defs = {}
          @field_defs.each do |k, v|
            field_defs[k] = v.clone
          end
          ordered = @ordered_fields.clone
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
        #     define_field :value3, MyClass, builder: ->(obj, type) { type.new(obj) }
        #   end
        #
        #   bs = BinaryStruct.new
        #   bs[value1]   # => Types::Int8
        #   bs.value1    # => Integer
        # @param [Symbol] name field name
        # @param [Object] type class or instance
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
          define = []
          if type < Types::Enum
            define << "def #{name}; self[:#{name}].to_i; end"
            define << "def #{name}=(val) self[:#{name}].value = val; end"
          elsif type < Types::Int
            define << "def #{name}; self[:#{name}].to_i; end"
            define << "def #{name}=(val) self[:#{name}].read val; end"
          elsif type.instance_methods.include?(:to_human) &&
                type.instance_methods.include?(:from_human)
            define << "def #{name}; self[:#{name}].to_human; end"
            define << "def #{name}=(val) self[:#{name}].from_human val; end"
          else
            define << "def #{name}; self[:#{name}]; end\n"
            define << "def #{name}=(val) self[:#{name}].read val; end"
          end

          define.delete(1) if type.instance_methods.include? "#{name}=".to_sym
          define.delete(0) if type.instance_methods.include? name
          class_eval define.join("\n")
          @field_defs[name] = [type, options.delete(:default),
                               options.delete(:builder),
                               options.delete(:optional),
                               options.delete(:enum),
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
        def define_field_before(other, name, type, options={})
          define_field name, type, options
          return if other.nil?

          @ordered_fields.delete name
          idx = @ordered_fields.index(other)
          raise ArgumentError, "unknown #{other} field" if idx.nil?

          @ordered_fields[idx, 0] = name
        end

        # Define a field, after another one
        # @param [Symbol,nil] other field name to create a new one after. If +nil+,
        #    new field is appended.
        # @param [Symbol] name field name to create
        # @param [Object] type class or instance
        # @param [Hash] options See {.define_field}.
        # @return [void]
        # @see .define_field
        def define_field_after(other, name, type, options={})
          define_field name, type, options
          return if other.nil?

          @ordered_fields.delete name
          idx = @ordered_fields.index(other)
          raise ArgumentError, "unknown #{other} field" if idx.nil?

          @ordered_fields[idx + 1, 0] = name
        end

        # Remove a previously defined field
        # @param [Symbol] name
        # @return [void]
        # @since 2.8.4
        def remove_field(name)
          @ordered_fields.delete name
          @field_defs.delete name
          undef_method name
          undef_method "#{name}="
        end

        # Delete a previously defined field
        # @param [Symbol] name
        # @return [void]
        # @deprecated Use {.remove_field} instead.
        # @since 2.8.4 deprecated
        def delete_field(name)
          Deprecation.deprecated(self, __method__, 'remove_field', klass_method: true)
          remove_field name
        end

        # Update a previously defined field
        # @param [Symbol] field field name to create
        # @param [Hash] options See {.define_field}.
        # @return [void]
        # @see .define_field
        # @raise [ArgumentError] unknown +field+
        # @since 2.8.4
        def update_field(field, options)
          raise ArgumentError, "unkown #{field} field for #{self}" unless @field_defs.key?(field)

          @field_defs[field][1] = options.delete(:default) if options.key?(:default)
          @field_defs[field][2] = options.delete(:builder) if options.key?(:builder)
          @field_defs[field][3] = options.delete(:optional) if options.key?(:optional)
          @field_defs[field][4] = options.delete(:enum) if options.key?(:enum)
          @field_defs[field][5].merge!(options)
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
        def define_bit_fields_on(attr, *args)
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
                class_eval <<-METHODS
                def #{field}?
                  val = (self[:#{attr}].to_i & #{field_mask}) >> #{shift}
                  val != 0
                end
                def #{field}=(v)
                  val = v ? 1 : 0
                  self[:#{attr}].value = self[:#{attr}].to_i & #{clear_mask}
                  self[:#{attr}].value |= val << #{shift}
                end
                METHODS
              else
                class_eval <<-METHODS
                def #{field}
                  (self[:#{attr}].to_i & #{field_mask}) >> #{shift}
                end
                def #{field}=(v)
                  self[:#{attr}].value = self[:#{attr}].to_i & #{clear_mask}
                  self[:#{attr}].value |= (v & #{2**size - 1}) << #{shift}
                end
                METHODS
              end

              @bit_fields[attr] = {} if @bit_fields[attr].nil?
              @bit_fields[attr][field] = size
            end

            idx -= size
            field = args.shift
          end
        end

        # Remove all bit fields defined on +attr+
        # @param [Symbol] attr attribute defining bit fields
        # @return [void]
        # @since 2.8.4
        def remove_bit_fields_on(attr)
          fields = @bit_fields.delete(attr)
          return if fields.nil?

          fields.each do |field, size|
            undef_method "#{field}="
            undef_method(size == 1 ? "#{field}?" : "#{field}")
          end
        end
      end

      # Create a new header object
      # @param [Hash] options Keys are symbols. They should have name of object
      #   attributes, as defined by {.define_field} and by {.define_bit_fields_on}.
      def initialize(options={})
        @fields = {}
        @optional_fields = {}

        self.class.class_eval { @field_defs }.each do |field, ary|
          type, default, builder, optional, enum, field_options = ary
          default = default.to_proc.call(self) if default.is_a?(Proc)
          @fields[field] = if builder
                             builder.call(self, type)
                           elsif enum
                             type.new(enum)
                           elsif !field_options.empty?
                             type.new(field_options)
                           else
                             type.new
                           end

          value = options[field] || default
          if value.class <= type
            @fields[field] = value
          elsif type < Types::Enum
            case value
            when ::String
              @fields[field].value = value
            else
              @fields[field].read(value)
            end
          elsif type < Types::Int
            @fields[field].read(value)
          elsif type <= Types::String
            @fields[field].read(value)
          elsif @fields[field].respond_to? :from_human
            @fields[field].from_human(value)
          end

          @optional_fields[field] = optional if optional
        end
        self.class.class_eval { @bit_fields }.each do |_, hsh|
          hsh.each_key do |bit_field|
            self.send "#{bit_field}=", options[bit_field] if options[bit_field]
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
        @ordered_fields ||= self.class.class_eval { @ordered_fields }
      end

      # Get all optional field name
      def optional_fields
        @optional_fields.keys
      end

      # Say if this field is optional
      # @return [Boolean]
      def optional?(field)
        @optional_fields.key? field
      end

      # @deprecated Use {#optional?} instead.
      def is_optional?(field)
        Deprecation.deprecated(self.class, __method__, 'optional?', klass_method: true)
        optional? field
      end

      # Say if an optional field is present
      # @return [Boolean]
      def present?(field)
        return true unless optional?(field)

        @optional_fields[field].call(self)
      end

      # Say if an optional field is present
      # @return [Boolean]
      # @deprecated Use {#present?} instead.
      def is_present?(field)
        Deprecation.deprecated(self.class, __method__, 'present?', klass_method: true)
        present? field
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

          obj = nil
          if self[field].respond_to? :width
            width = self[field].width
            obj = self[field].read str[start, width]
            start += width
          elsif self[field].respond_to? :sz
            obj = self[field].read str[start..-1]
            size = self[field].sz
            start += size
          else
            obj = self[field].read str[start..-1]
            start = str.size
          end
          self[field] = obj unless obj == self[field]
        end

        self
      end

      # Common inspect method for headers
      # @return [String]
      def inspect
        str = Inspect.dashed_line(self.class, 1)
        fields.each do |attr|
          next if attr == :body
          next unless present?(attr)

          str << Inspect.inspect_attribute(attr, self[attr], 1)
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
        Hash[fields.map { |f| [f, @fields[f].to_human] }]
      end

      # Used to set body as value of body object.
      # @param [String,Int,Fields,nil] value
      # @return [void]
      # @raise [BodyError] no body on given object
      # @raise [ArgumentError] cannot cram +body+ in +:body+ field
      # @deprecated
      def body=(value)
        Deprecation.deprecated(self.class, __method__)
        raise BodyError, 'no body field' unless @fields.key? :body

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
      # @deprecated Will be a private method
      def force_binary(str)
        PacketGen.force_binary(str)
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
        self.class.class_eval { @bit_fields }[field]
      end

      private

      # Deeply duplicate +@fields+
      # @return [void]
      def initialize_copy(_other)
        fields = {}
        @fields.each { |k,v| fields[k] = v.dup }
        @fields = fields
      end
    end
  end
end
