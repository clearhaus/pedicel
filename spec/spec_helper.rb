require 'securerandom'
require 'base64'

def ec_key_to_pkey_public_key(ec_key)
  # EC#public_key is not a PKey public key, but an EC point.
  pub = OpenSSL::PKey::EC.new(ec_key.group)
  pub.public_key = ec_key.is_a?(OpenSSL::PKey::PKey) ? ec_key.public_key : ec_key

  pub
end
