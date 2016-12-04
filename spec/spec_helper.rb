require 'simplecov'
SimpleCov.start do
  add_filter "/spec/"
  add_filter "/vendor/"
end

RSpec.configure do |c|
  if c.filter[:sudo]
    SimpleCov.command_name 'rspec:sudo'
  end
  c.include CaptureHelper
end

$LOAD_PATH.unshift File.join(File.dirname(__FILE__), '..', 'lib')
require 'packetgen'

Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].each {|f| require f}
