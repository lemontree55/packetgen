module PacketGen
  module Header

    module HeaderClassMethods

      # Simple class to handle layer association
      Layer = Struct.new(:key, :value)

      # Bind a upper layer to current class
      # @param [Class] header_klass header class to bind to current class
      # @param [Hash] args current class field and its value when +header_klass+
      #  is embedded in current class
      # @return [void]
      def bind_layer(header_klass, args={})
        @known_layers ||= {}
        key = args.keys.first
        @known_layers[header_klass] = Layer.new(key, args[key])
      end

      # Get knwon layers
      # @return [Hash] keys: header classes, values: struct with methods #key and #value
      def known_layers
        @known_layers ||= {}
      end
    end

  end
end
