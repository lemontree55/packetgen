module PacketGen
  # Deprecation module
  # @since 2.6.1
  # @author Sylvain Daubert
  # @api private
  module Deprecation
    def self.deprecated(klass, deprecated_method, new_method, klass_method: false, remove_version: '3.0.0')
      separator = klass_method ? '.' : '#'
      base_name = klass.to_s + separator
      complete_deprecated_method_name = base_name + deprecated_method.to_s
      complete_new_method_name = base_name + new_method.to_s

      warn "#{complete_deprecated_method_name} is deprecated in favor of #{complete_new_method_name}. " \
           "It will be remove in PacketGen #{remove_version}."
    end
  end
end
