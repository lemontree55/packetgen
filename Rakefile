# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'yard'
require 'yard/doctest/rake'

task default: :spec

RSpec::Core::RakeTask.new do |t|
  t.rspec_opts = '-t ~sudo'
end
RSpec::Core::RakeTask.new('spec:sudo') do |t|
  t.rspec_opts = if ENV['TRAVIS']
                   '-t sudo -t ~notravis'
                 else
                   '-t sudo'
                 end
end

YARD::Rake::YardocTask.new do |t|
  t.options = ['--no-private']
  t.files = ['lib/**/*.rb', '-', 'LICENSE']
end
YARD::Doctest::RakeTask.new

begin
  require 'rubocop/rake_task'

  RuboCop::RakeTask.new do |task|
    task.patterns = ['lib/**/*.rb']
  end
rescue LoadError # rubocop:disable Lint/SuppressedException
end
