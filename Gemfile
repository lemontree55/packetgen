# frozen_string_literal: true

source 'https://rubygems.org'

# Specify your gem's dependencies in packetgen.gemspec
gemspec

gem 'bundler', '>=2.2', '<3'

group :develoment do
  gem 'rake', '~> 13.0'
  gem 'rspec', '~> 3.12'
  gem 'ruby-lsp'
  gem 'yard', '~> 0.9'
end

group :noci do
  gem 'simplecov', '~> 0.22'
end

group :rubocop do
  gem 'rubocop', '~> 1.50', require: false
  gem 'rubocop-performance', '~>1.17', require: false
end
