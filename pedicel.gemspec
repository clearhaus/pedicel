lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'pedicel/version'

Gem::Specification.new do |s|
  s.name     = 'pedicel'
  s.version  = Pedicel::VERSION
  s.author   = 'Clearhaus'
  s.email    = 'hello@clearhaus.com'
  s.summary  = 'Decryption of Apple Pay payment tokens'
  s.homepage = 'https://github.com/clearhaus/pedicel'
  s.license  = 'MIT'

  s.files = Dir.glob("lib/**/*.rb")

  s.add_runtime_dependency 'dry-validation', '~> 1.9'
  s.add_runtime_dependency 'dry-schema', '~> 1.9'
  s.add_runtime_dependency 'dry-logic', '~> 1.0'

  s.required_ruby_version = '>= 2.7.4', '<= 3.2'

  # s.add_development_dependency 'pedicel-pay'
  s.add_development_dependency 'pry', '~> 0.0'
  s.add_development_dependency 'rake', '~> 12.3'
  s.add_development_dependency 'rspec', '~> 3.7'
end
