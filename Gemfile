source 'https://rubygems.org'

require 'openssl'
unless OpenSSL::Cipher.new('aes-256-gcm').respond_to?(:iv_len=)
  gem 'aes256gcm_decrypt', :git => 'https://github.com/clearhaus/aes256gcm_decrypt'
end

gemspec
