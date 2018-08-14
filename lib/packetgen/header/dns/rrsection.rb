# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    class DNS
      # Define a DNS Ressource Record Section
      # @author Sylvain Daubert
      class RRSection < Types::Array
        # @api private
        # @param [DNS] dns
        # @param [Types::Int] counter
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
          force_binary str
          while !str.empty? && (self.size < @counter.to_i)
            rr = RR.new(@dns).read(str)
            rr = OPT.new(@dns).read(str) if rr.has_type?('OPT')
            str.slice!(0, rr.sz)
            push rr
          end
          self
        end

        private

        def record_from_hash(hsh)
          if hsh.key? :rtype
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
