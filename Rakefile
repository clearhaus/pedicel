require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

task :test do
  require 'rspec/core'
  exit RSpec::Core::Runner.run(['spec'])
end

task default: :test
