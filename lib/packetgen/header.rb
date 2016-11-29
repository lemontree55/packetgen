module PacketGen
  # Namespace for protocol header classes
  # @author Sylvain Daubert
  module Header

    # Get known header classes
    # @return [Array<Class>]
    def self.all
      constants.map { |sym| const_get sym }.
        select { |klass| klass < Struct && klass < HeaderMethods }
    end
  end
end

require_relative 'header/header_class_methods'
require_relative 'header/header_methods'
require_relative 'header/eth'
require_relative 'header/ip'
require_relative 'header/arp'
require_relative 'header/udp'
