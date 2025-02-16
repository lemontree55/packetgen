# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class DNS
      # Define a DNS Ressource Record Section
      # @author Sylvain Daubert
      class RRSection < BinStruct::Array
        # @api private
        # @param [DNS] dns
        # @param [BinStruct::Int] counter
        def initialize(dns, counter)
          super(counter: counter)
          @dns = dns
        end

        # Read RR section from a string
        # @param [String] str binary string
        # @return [RRSection] self
        def read(str)
          clear
          return self if str.nil?

          str = str.b unless str.encoding == Encoding::BINARY
          while !str.empty? && (self.size < @counter.to_i)
            rr = RR.new(@dns).read(str)
            rr = OPT.new(@dns).read(str) if rr.type?('OPT')
            str.slice!(0, rr.sz)
            push(rr)
          end
          self
        end

        private

        def record_from_hash(hsh)
          if hsh.key?(:rtype)
            case hsh.delete(:rtype)
            when 'Question'
              Question.new(@dns, hsh)
            when 'OPT'
              OPT.new(@dns, hsh)
            when 'RR'
              RR.new(@dns, hsh)
            else
              raise TypeError, 'rtype should be a Question, OPT or RR'
            end
          else
            hsh
          end
        end
      end
    end
  end
end
