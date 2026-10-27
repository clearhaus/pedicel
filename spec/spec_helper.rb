require 'securerandom'
require 'base64'
require 'openssl'

# pedicel-pay 0.0.8 calls OpenSSL::PKey::EC.new with no arguments to see
# whether EC keys implement private?. OpenSSL 3 rejects that constructor.
begin
  OpenSSL::PKey::EC.new
rescue ArgumentError => e
  raise unless e.message.include?('cannot be called without arguments')

  class << OpenSSL::PKey::EC
    alias_method :new_with_arguments, :new

    def new(*args)
      return new_with_arguments('prime256v1') if args.empty?

      new_with_arguments(*args)
    end
  end
end
