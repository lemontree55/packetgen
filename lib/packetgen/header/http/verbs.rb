# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # @since 2.2.0
    # @author Kent 'picat' Gruber
    module HTTP
      # Valid HTTP Verbs
      VERBS = %w[GET HEAD POST PUT DELETE CONNECT OPTIONS TRACE PATCH].freeze

      # Identifiable HTTP request regular expression.
      REQUEST_REGEX = Regexp.new("^(#{VERBS.dup.join('|')})\\s+\\S+\\s+HTTP/1.1")
    end
  end
end
