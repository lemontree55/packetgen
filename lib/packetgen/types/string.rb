# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Types

    # This class is just like regular String. It only adds #read and #sz methods
    # to be compatible with others {Types}.
    # @author Sylvain Daubert
    class String < ::String

      # @param [::String] str
      # @return [String] self
      def read(str)
        self.replace str.to_s
        self
      end

      alias sz length
    end
  end
end
