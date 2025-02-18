# frozen_string_literal: true

module PacketGen
  # Deprecation module
  # @since 2.7.0
  # @author Sylvain Daubert
  # @api private
  module Deprecation
    # Default remove version for deprecated classes/methods
    # @since 3.1.0
    REMOVE_VERSION = '5.0.0'

    # @private
    # @param [String] remove_version
    # @return [String]
    # @since 3.1.4
    def self.removed(remove_version)
      "It will be removed in PacketGen #{remove_version}"
    end

    # Warn when using a deprecated method
    # @param [Module] klass class/module of deprecated method
    # @param [Symbol,String] deprecated_method
    # @param [Symbol,String,nil] new_method method to use instead of deprecated one
    # @param [Boolean] klass_method +deprecated_method+ is a class method (+true+)
    #                  or a, instance one (+false+)
    # @param [String] remove_version version from which +deprecated_method+ will
    #                 no more exist.
    def self.deprecated(klass, deprecated_method, new_method=nil, klass_method: false, remove_version: REMOVE_VERSION)
      base_name = "#{klass}#{klass_method ? '.' : '#'}"
      complete_deprecated_method_name = "#{base_name}#{deprecated_method}"
      unless new_method.nil?
        complete_new_method_name = if %w[# .].any? { |punct| new_method.include?(punct) }
                                     new_method
                                   else
                                     "#{base_name}#{new_method}"
                                   end
      end

      file, line = caller(2..2).first.split(':')[0, 2]
      message = "#{file}:#{line}: #{complete_deprecated_method_name} is deprecated"
      message << " in favor of #{complete_new_method_name}" unless new_method.nil?
      message << '. ' << self.removed(remove_version)
      warn(message)
    end

    # Warn when using a deprecated method
    # @param [Module] klass deprecated class/module
    # @param [Module] new_klass class/module to use instead of +klass+
    # @param [String] remove_version version from which +klass+ will
    #                 no more exist.
    # @since 3.1.0
    def self.deprecated_class(klass, new_klass=nil, remove_version: REMOVE_VERSION)
      file, line = caller(2..2).first.split(':')[0, 2]
      message = "#{file}:#{line}: #{klass} is deprecated"
      message << " in favor of #{new_klass}" unless new_klass.nil?
      message << '. ' << self.removed(remove_version)
      warn(message)
    end

    # Warn when using a deprecated method's option
    # @param [Module] klass deprecated class/module
    # @param [Module] method method name
    # @param [Symbol] option option name
    # @param [Boolean] klass_method +deprecated_method+ is a class method (+true+)
    #                  or a, instance one (+false+)
    # @param [String] remove_version version from which +klass+ will
    #                 no more exist.
    # @since 3.1.4
    def self.deprecated_option(klass, method, option, klass_method: false, remove_version: REMOVE_VERSION)
      base_name = "#{klass}#{klass_method ? '.' : '#'}"
      method_name = "#{base_name}#{method}"
      message = "option #{option} is deprecated for method #{method_name}. "
      message << self.removed(remove_version)
      warn(message)
    end
  end
end
