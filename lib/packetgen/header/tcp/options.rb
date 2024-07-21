# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

require_relative 'option'

module PacketGen
  module Header
    class TCP
      # Container for TCP options in {TCP TCP header}.
      # @author Sylvain Daubert
      class Options < BinStruct::Array
        set_of Option

        # Get {Option} subclasses
        # @return [Array<Class>]
        def self.option_classes
          return @klasses if defined? @klasses

          @klasses = []
          Option.constants.each do |cst|
            next unless cst.to_s.end_with? '_KIND'

            optname = cst.to_s.sub('_KIND', '')
            @klasses[Option.const_get(cst)] = TCP.const_get(optname)
          end
          @klasses
        end

        private

        def record_from_hash(hsh)
          if hsh.key? :opt
            klassname = hsh.delete(:opt)
            raise ArgumentError, 'opt should be a TCP::Option subclass' unless TCP.const_defined?(klassname)

            klass = TCP.const_get(klassname)
            raise ArgumentError, 'opt should be a TCP::Option subclass' unless klass < Option

            klass.new(hsh)
          else
            hsh
          end
        end

        def real_type(opt)
          klasses = self.class.option_classes
          klasses[opt.kind].nil? ? Option : klasses[opt.kind]
        end
      end
    end
  end
end
