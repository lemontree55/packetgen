module PacketGen
  module Header
    class DNS

      # DNS option
      # @author Sylvain Daubert
      class Option < Types::TLV

        # Force {#type} and {#length} fields to be {Types::Int16}
        # @see TLV#initialize
        def initialize(options={})
          super options.merge!(t: Types::Int16, l: Types::Int16)
        end
      end
    end
  end
end
