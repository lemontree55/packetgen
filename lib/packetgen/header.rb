module PacketGen
  # Namespace for protocol header classes
  module Header
  end
end

require_relative 'header/header_class_methods'
require_relative 'header/eth'
require_relative 'header/ip'
