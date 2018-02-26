require 'pedicel'

require 'spec_helper'

require 'json'

describe 'basic test' do
  it 'works' do
    symmetric_key = OpenSSL::Digest::SHA256.new.update('secret').digest

    data = PedicelPay::Token::Data.sample

    token = PedicelPay::Token.new(
      data: data.encrypted_with(symmetric_key: symmetric_key),
      ephemeral_public_key: 'symkey-test',
      public_key_hash: 'symkey-test',
      transaction_id: Random.new.bytes(5).unpack('H*').first
    )

    p = Pedicel::EC.new(JSON.parse(token.to_json))

    expect(p.decrypt_aes(key: symmetric_key)).to eq(data.json)
  end

  it 'works' do
    backend = PedicelPay::Backend.new
    Pedicel.config.merge!(apple_root_ca_g3_cert_pem: backend.ca_cert.to_pem)
    merchant = PedicelPay::Merchant.new

    merchant_certificate = backend.sign_csr(merchant.csr)
    shared_secret, ephemeral_public_key = backend.shared_secret_and_ephemeral_public_key(merchant_certificate: merchant_certificate)

    symmetric_key = backend.symmetric_key(certificate: merchant_certificate, shared_secret: shared_secret)

    data = PedicelPay::Token::Data.sample

    token = PedicelPay::Token.new(
      data: data.encrypted_with(symmetric_key: symmetric_key),
      ephemeral_public_key: ephemeral_public_key,
      public_key_hash: 'foobar',
      transaction_id: Random.new.bytes(5)
    )
    token.signature = backend.sign(
      ephemeral_public_key: token.ephemeral_public_key,
      encrypted_data: token.data,
      transaction_id: token.transaction_id
    )

    p = Pedicel::EC.new(JSON.parse(token.to_json))

    expect(p.decrypt(private_key: merchant.key, certificate: merchant_certificate)).to eq(data.json)
  end
end
