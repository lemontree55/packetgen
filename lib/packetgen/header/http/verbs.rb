# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen
  module Header
    # @since 2.2.0
    module HTTP
      # @abstract Collection of useful HTTP verbs.
      # @author Kent 'picat' Gruber

      # Valid HTTP Verbs
      VERBS = %w[GET HEAD POST PUT DELETE CONNECT OPTIONS TRACE PATCH].freeze

      # Identifiable HTTP request regular expression.
      REQUEST_REGEX = Regexp.new('(' + VERBS.dup.join('|') + ')' + '\s+\S+\s+HTTP/1.1')
    end
  end
end
