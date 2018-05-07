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

  s.add_runtime_dependency 'dry-validation', '~> 0.11.1'

  s.required_ruby_version = '~> 2.3'
  #s.required_ruby_version = ['< 2.4', '~> 2.3']
  s.add_runtime_dependency 'aes256gcm_decrypt', '~> 0.0.2'

  s.add_development_dependency 'rake'
  s.add_development_dependency 'rspec', '~> 3.7'
  s.add_development_dependency 'pry', '~> 0.11'
  s.add_development_dependency 'pedicel-pay'
end
