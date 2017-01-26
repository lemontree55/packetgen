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
          force_binary str
          while str.length > 0 and self.size < @counter.to_i
            question = Question.new(@dns).read(str)
            str.slice!(0, question.sz)
            self.push question
          end
          self
        end
      end
    end
  end
end

