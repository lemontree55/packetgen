module PacketGen
  module Header
    class DNS

      # @author Sylvain Daubert
      class Option < Base

        # @!attribute code
        #  @return [Integer]
        define_field :code, Types::Int16
        # @!attribute length
        #  @return [Integer]
        define_field :length, Types::Int16
        # @!attribute data
        #  @return [Types::String]
        define_field :data, Types::String

        # @return [String]
        def to_human
          "code=#{code},len=#{length},data=#{data.inspect}"
        end
      end
    end
  end
end
