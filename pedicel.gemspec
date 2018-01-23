Gem::Specification.new do |s|
  s.name    = 'pedicel'
  s.version = '0.0.1'
  s.summary = 'Handle Apple Pay PaymentTokens'
  s.author  = 'Clearhaus'

  s.files = Dir.glob("lib/**/*.rb")

  s.add_runtime_dependency 'dry-validation'

  require 'openssl'
  unless OpenSSL::Cipher.new('aes-256-gcm').respond_to?(:iv_len=)
    s.add_runtime_dependency 'aes256gcm_decrypt'
  end

  s.add_development_dependency 'rspec', '~> 3.7'
  s.add_development_dependency 'pry', '~> 0.11'
end
