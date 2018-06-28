require 'pedicel-pay'

def token
  backend = PedicelPay::Backend.generate
  client = backend.generate_client

  token = PedicelPay::Token.new.sample
  backend.encrypt_and_sign(token, recipient: client)

  token
end
