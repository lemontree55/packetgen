module PacketGen
  module Header
    class DNS

      # @author Sylvain Daubert
      class Option < Base

        # @!attribute code
        #  @return [Integer]
        define_field :code, StructFu::Int16
        # @!attribute length
        #  @return [Integer]
        define_field :length, StructFu::Int16
        # @!attribute data
        #  @return [StructFu::String]
        define_field :data, StructFu::String

        # @return [String]
        def to_human
          "code=#{code},len=#{length},data=#{data.inspect}"
        end
      end
    end
  end
end
