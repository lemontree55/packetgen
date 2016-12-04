require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'yard'

task :default => :spec

RSpec::Core::RakeTask.new do |t|
  t.rspec_opts = '-t ~sudo'
end
RSpec::Core::RakeTask.new('spec:sudo') do |t|
  t.rspec_opts = '-t sudo'
end

YARD::Rake::YardocTask.new do |t|
  t.options = ['--no-private']
  t.files = ['lib/**/*.rb', '-', 'LICENSE']
end

