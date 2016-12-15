# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    module HeaderClassMethods

      # Simple class to handle header association
      Binding = Struct.new(:key, :value)

      # Bind a upper header to current class
      # @param [Class] header_klass header class to bind to current class
      # @param [Hash] args current class field and its value when +header_klass+
      #  is embedded in current class
      # @return [void]
      def bind_header(header_klass, args={})
        @known_headers ||= {}
        key = args.keys.first
        @known_headers[header_klass] = Binding.new(key, args[key])
      end

      # Get knwon headers
      # @return [Hash] keys: header classes, values: struct with methods #key and #value
      def known_headers
        @known_headers ||= {}
      end
    end

  end
end
