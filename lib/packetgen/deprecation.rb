# frozen_string_literal: true

module PacketGen
  # Deprecation module
  # @since 2.7.0
  # @author Sylvain Daubert
  # @api private
  module Deprecation
    # Default remove version for deprecated classes/methods
    # @since 3.1.0
    REMOVE_VERSION = '4.0.0'

    # Warn when using a deprecated method
    # @param [Module] klass class/module of deprecated method
    # @param [Symbol,String] deprecated_method
    # @param [Symbol,String,nil] new_method method to use instead of deprecated one
    # @param [Boolean] klass_method +deprecated_method+ is a class method (+true+)
    #                  or a, instance one (+false+)
    # @param [String] remove_version version from which +deprecated_method+ will
    #                 no more exist.
    def self.deprecated(klass, deprecated_method, new_method=nil, klass_method: false, remove_version: REMOVE_VERSION)
      separator = klass_method ? '.' : '#'
      base_name = klass.to_s + separator
      complete_deprecated_method_name = base_name + deprecated_method.to_s
      complete_new_method_name = base_name + new_method.to_s unless new_method.nil?

      file, line = caller(2..2).split(':')[0, 2]
      message = +"#{file}:#{line}: #{complete_deprecated_method_name} is deprecated"
      message << " in favor of #{complete_new_method_name}" unless new_method.nil?
      message << ". It will be remove in PacketGen #{remove_version}."
      warn message
    end

    # Warn when using a deprecated method
    # @param [Module] klass deprecated class/module
    # @param [Module] new_klass class/module to use instead of +klass+
    # @param [String] remove_version version from which +klass+ will
    #                 no more exist.
    # @since 3.1.0
    def self.deprecated_class(klass, new_klass=nil, remove_version: REMOVE_VERSION)
      file, line = caller(2..2).first.split(':')[0, 2]
      message = +"#{file}:#{line}: #{klass} is deprecated"
      message << " in favor of #{new_klass}" unless new_klass.nil?
      message << ". It will be remove in PacketGen #{remove_version}."
      warn message
    end
  end
end
