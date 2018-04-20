# frozen_string_literal: true

require 'pedicel'
require 'pedicel-pay'

require 'pry'

# rubocop:disable Metrics/BlockLength

describe 'Pedicel::EC decrypt function' do
  context 'should succeed on valid arguments' do
    it '(symmetric_key)' do
      backend, merchant, token, _data = PedicelPay::Helper.generate_all

      p = Pedicel::EC.new(
        JSON.parse(token.to_json),
        config: Pedicel::DEFAULTS.merge(
          trusted_ca_pem: backend.ca_certificate
        )
      )

      symmetric_key = p.symmetric_key(
        certificate: merchant.certificate,
        private_key: merchant.key
      )

      decrypted = p.decrypt(
        symmetric_key: symmetric_key
      )

      expect(decrypted).to be_truthy
      expect(decrypted).to eq(token.unencrypted_data.to_json)
    end

    it '(merchant, private_key)' do
      backend, merchant, token, _data = PedicelPay::Helper.generate_all

      p = Pedicel::EC.new(
        JSON.parse(token.to_json),
        config: Pedicel::DEFAULTS.merge(
          trusted_ca_pem: backend.ca_certificate
        )
      )

      decrypted = p.decrypt(
        certificate: merchant.certificate,
        private_key: merchant.key
      )

      expect(decrypted).to be_truthy
      expect(decrypted).to eq(token.unencrypted_data.to_json)
    end

    it '(merchant_id, private_key)' do
      backend, merchant, token, _data = PedicelPay::Helper.generate_all

      p = Pedicel::EC.new(
        JSON.parse(token.to_json),
        config: Pedicel::DEFAULTS.merge(
          trusted_ca_pem: backend.ca_certificate
        )
      )

      decrypted = p.decrypt(
        merchant_id: merchant.merchant_id,
        private_key: merchant.key
      )

      expect(decrypted).to be_truthy
      expect(decrypted).to eq(token.unencrypted_data.to_json)
    end
  end

  context 'should fail on' do
    it 'excessive arguments' do
      backend, merchant, token, _data = PedicelPay::Helper.generate_all

      p = Pedicel::EC.new(
        JSON.parse(token.to_json),
        config: Pedicel::DEFAULTS.merge(
          trusted_ca_pem: backend.ca_certificate
        )
      )

      merchant_id = merchant.merchant_id
      certificate = merchant.certificate
      private_key = merchant.key
      symmetric_key = p.symmetric_key(
        certificate: merchant.certificate,
        private_key: merchant.key
      )

      expect do
        p.decrypt(
          merchant_id: merchant_id,
          certificate: certificate,
          private_key: private_key
        )
      end.to raise_error(ArgumentError)

      expect do
        p.decrypt(
          merchant_id: merchant_id,
          private_key: private_key,
          symmetric_key: symmetric_key
        )
      end.to raise_error(ArgumentError)

      expect do
        p.decrypt(
          certificate: certificate,
          private_key: private_key,
          symmetric_key: symmetric_key
        )
      end.to raise_error(ArgumentError)

      # Currently you can actually use all arguments
      # Changing this seems folly, as it is not really important.
    end
  end
end

describe 'Pedicel::EC.merchant_id' do
  it 'should raise CertificateError on invalid certificate' do
    expect do
      garbage = Base64.strict_encode64(Random.new.bytes(200))
      Pedicel::EC.merchant_id(certificate: garbage)
    end.to raise_error(Pedicel::CertificateError)
  end
end

describe 'Pedicel::EC::verify_signature' do
  it 'should raise CertificateError when root CA is invalid' do
    _, _, token = PedicelPay::Helper.generate_all
    garbage = Base64.strict_encode64(Random.new.bytes(200))

    p = Pedicel::EC.new(
      JSON.parse(token.to_json),
      config: Pedicel::DEFAULTS.merge(
        trusted_ca_pem: garbage
      )
    )

    expect do
      p.verify_signature
    end.to raise_error(Pedicel::CertificateError)
  end
end
#
# rubocop:enable Metrics/BlockLength
