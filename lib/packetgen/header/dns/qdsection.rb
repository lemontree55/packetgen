# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class DNS
      # Define a DNS Question Section
      # @author Sylvain Daubert
      class QDSection < RRSection
        # @!method push(q)
        #  Add a question to this section without incrementing associated counter
        #  @param [Question,Hash] q
        #  @return [QDSection] self
        # @!method <<(q)
        #  Add a question to this section. Increment associated counter
        #  @param [Question,Hash] q
        #  @return [QDSection] self
        # @!method delete(q)
        #  Delete a question
        #  @param [Question] q
        #  @return [Question]

        # Read Question section from a string
        # @param [String] str binary string
        # @return [QDSection] self
        def read(str)
          clear
          return self if str.nil?

          str = str.b unless str.encoding == Encoding::ASCII_8BIT
          while !str.empty? && (self.size < @counter.to_i)
            question = Question.new(@dns).read(str)
            str.slice!(0, question.sz)
            push(question)
          end
          self
        end
      end
    end
  end
end
