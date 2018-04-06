# frozen_string_literal: true

require 'pedicel'
require 'pedicel-pay'

require 'openssl'
require 'json'
require 'pry'

describe 'decryption' do
  let(:pedicel) { Pedicel.new }

  context 'with valid backend' do
    it 'works with symmetric key' do
      backend = PedicelPay::Backend.generate
      client = backend.generate_client

      _, eph_key = backend.generate_shared_secret_and_ephemeral_pubkey(
        recipient: client
      )

      symmetric_key = OpenSSL::Digest::SHA256.new.update('secret').digest
      token_data = PedicelPay::TokenData.new.sample

      token_header = PedicelPay::TokenHeader.new(
        ephemeral_pubkey: eph_key
      ).sample

      encrypted = PedicelPay::Helper.encrypt(
        data: token_data.to_json,
        key: symmetric_key
      )

      token = PedicelPay::Token.new(
        unencrypted_data: token_data,
        encrypted_data: encrypted,
        header: token_header
      )

      token.update_pubkey_hash(
        recipient: client
      )

      backend.sign(token,
                   backend.intermediate_certificate,
                   backend.intermediate_key)

      p = Pedicel::EC.new(JSON.parse(token.to_json))

      expect(p.decrypt_aes(key: symmetric_key)).to eq(token_data.to_json)
    end

    # Test that a normal flow works.
    it 'works with ephemeral assymetric encryption' do
      backend, merchant, token, data = PedicelPay::Helper.generate_all

      # Overwrite default CA in pedicel.
      Pedicel.config =
        Pedicel::DEFAULTS.merge(
          apple_root_ca_g3_cert_pem: backend.ca_certificate.to_pem
        ).freeze

      p = Pedicel::EC.new(JSON.parse(token.to_json))

      decrypted =
        p.decrypt(
          merchant_id: merchant.merchant_id,
          private_key: merchant.key,
          certificate: merchant.certificate
        )

      expect(decrypted).to eq(data.to_json)
    end

    it 'validates with ephemeral assymetric encryption' do
      pending
      backend, merchant, token, data = PedicelPay::Helper.generate_all

      # Overwrite default CA in pedicel.
      Pedicel.config =
        Pedicel::DEFAULTS.merge(
          apple_root_ca_g3_cert_pem: backend.ca_certificate.to_pem
        ).freeze

      p = Pedicel::EC.new(JSON.parse(token.to_json))

      expect(p.validate_content).to be true
    end
  end

  # Make sure that token with an invalid root certificate are rejected.
  # The default root certificate does not correspond to the root certificate
  # for this token.

  context('with invalid root certificate') do
    it 'fails with signature error' do
      _, merchant, token = PedicelPay::Helper.generate_all

      p = Pedicel::EC.new(JSON.parse(token.to_json))

      # NOTE: Pedicel Root Certificate is not replaced with testing CA!

      expect do
        p.decrypt(
          merchant_id: merchant.merchant_id,
          private_key: merchant.key,
          certificate: merchant.certificate
        )
      end.to raise_error(Pedicel::SignatureError)
    end
  end

  it 'unsigned intermediate certificate' do
    backend, merchant, token = PedicelPay::Helper.generate_all(
      pp_config: PedicelPay.config.merge(
        # Option to avoid signing intermediate
        sign_intermediate: false
      )
    )

    # Self-sign the intermediate, as this is a "valid" signature.
    backend.intermediate_certificate.sign(backend.intermediate_key,
                                          OpenSSL::Digest::SHA256.new)

    p = Pedicel::EC.new(JSON.parse(token.to_json))

    # Overwrite default CA in pedicel.
    Pedicel.config[:apple_root_ca_g3_cert_pem] = backend.ca_certificate.to_pem

    expect do
      p.decrypt(
        merchant_id: merchant.merchant_id,
        private_key: merchant.key,
        certificate: merchant.certificate
      )
    end.to raise_error(Pedicel::SignatureError)
  end

  it 'unsigned leaf certificate' do
    backend, merchant, token = PedicelPay::Helper.generate_all(
      pp_config: PedicelPay.config.merge(
        # Option to avoid signing intermediate
        sign_leaf: false
      )
    )

    # Self-sign the leaf, as this is a "valid" signature.
    backend.leaf_certificate.sign(backend.leaf_key, OpenSSL::Digest::SHA256.new)

    p = Pedicel::EC.new(JSON.parse(token.to_json))

    # Overwrite default CA in pedicel.
    Pedicel.config[:apple_root_ca_g3_cert_pem] = backend.ca_certificate.to_pem

    expect do
      p.decrypt(
        merchant_id: merchant.merchant_id,
        private_key: merchant.key,
        certificate: merchant.certificate
      )
    end.to raise_error(Pedicel::SignatureError)
  end

  it 'self-signed intermediate certificate' do
    backend, merchant, token = PedicelPay::Helper.generate_all(
      pp_config: PedicelPay.config.merge(
        # Option to avoid signing intermediate
        sign_intermediate: false
      )
    )

    backend.intermediate_certificate, backend.intermediate_key =
      PedicelPay::Backend.generate_ca

    p = Pedicel::EC.new(JSON.parse(token.to_json))

    # Overwrite default CA in pedicel.
    Pedicel.config[:apple_root_ca_g3_cert_pem] = backend.ca_certificate.to_pem

    expect do
      p.decrypt(
        merchant_id: merchant.merchant_id,
        private_key: merchant.key,
        certificate: merchant.certificate
      )
    end.to raise_error(Pedicel::SignatureError)
  end

  it 'missing intermediate OID' do
    backend, merchant, token = PedicelPay::Helper.generate_all(
      pp_config: PedicelPay.config.merge(
        custom_intermediate_oid: false
      )
    )

    p = Pedicel::EC.new(JSON.parse(token.to_json))
    Pedicel.config[:apple_root_ca_g3_cert_pem] = backend.ca_certificate.to_pem

    expect do
      p.decrypt(
        merchant_id: merchant.merchant_id,
        private_key: merchant.key,
        certificate: merchant.certificate
      )
    end.to raise_error(Pedicel::SignatureError)
  end

  it 'missing leaf OID' do
    backend, merchant, token = PedicelPay::Helper.generate_all(
      pp_config: PedicelPay.config.merge(
        custom_leaf_oid: false
      )
    )

    p = Pedicel::EC.new(JSON.parse(token.to_json))
    Pedicel.config[:apple_root_ca_g3_cert_pem] = backend.ca_certificate.to_pem

    expect do
      p.decrypt(
        merchant_id: merchant.merchant_id,
        private_key: merchant.key,
        certificate: merchant.certificate
      )
    end.to raise_error(Pedicel::SignatureError)
  end

  it 'unsigned token' do
    backend, merchant, token = PedicelPay::Helper.generate_all(
      pp_config: PedicelPay.config.merge(
        sign_token: false
      )
    )

    p = Pedicel::EC.new(JSON.parse(token.to_json))
    Pedicel.config[:apple_root_ca_g3_cert_pem] = backend.ca_certificate.to_pem

    expect do
      p.decrypt(
        merchant_id: merchant.merchant_id,
        private_key: merchant.key,
        certificate: merchant.certificate
      )
    end.to raise_error(Pedicel::SignatureError)
  end

  it 'signature not by leaf' do
    backend, merchant, token = PedicelPay::Helper.generate_all(
      pp_config: PedicelPay.config.merge(
        sign_token: false
      )
    )

    fake_backend, = PedicelPay::Helper.generate_all

    fake_backend.sign(
      token,
      fake_backend.leaf_certificate,
      fake_backend.leaf_key
    )

    p = Pedicel::EC.new(JSON.parse(token.to_json))
    Pedicel.config[:apple_root_ca_g3_cert_pem] = backend.ca_certificate.to_pem

    expect do
      p.decrypt(
        merchant_id: merchant.merchant_id,
        private_key: merchant.key,
        certificate: merchant.certificate
      )
    end.to raise_error(Pedicel::SignatureError)
  end

  it 'swapped OIDs' do
    backend, merchant, token = PedicelPay::Helper.generate_all(
      pp_config: PedicelPay.config.merge(
        oid: {
          leaf_certificate:          '1.2.840.113635.100.6.2.14',
          intermediate_certificate:  '1.2.840.113635.100.6.29'
        }
      )
    )

    p = Pedicel::EC.new(JSON.parse(token.to_json))
    Pedicel.config[:apple_root_ca_g3_cert_pem] = backend.ca_certificate.to_pem

    expect do
      p.decrypt(
        merchant_id: merchant.merchant_id,
        private_key: merchant.key,
        certificate: merchant.certificate
      )
    end.to raise_error(Pedicel::SignatureError)
  end

  it 'too old token' do
    backend, merchant, token = PedicelPay::Helper.generate_all

    # Overwrite default CA in pedicel.
    Pedicel.config[:apple_root_ca_g3_cert_pem] = backend.ca_certificate.to_pem

    p = Pedicel::EC.new(JSON.parse(token.to_json))

    expect do
      p.decrypt(
        merchant_id: merchant.merchant_id,
        private_key: merchant.key,
        certificate: merchant.certificate,
        now: Time.now + Pedicel.config[:replay_threshold_seconds] + 1
      )
    end.to raise_error(Pedicel::SignatureError)
  end

  it 'token signed in the future' do
    backend, merchant, token = PedicelPay::Helper.generate_all

    # Overwrite default CA in pedicel.
    Pedicel.config[:apple_root_ca_g3_cert_pem] = backend.ca_certificate.to_pem

    p = Pedicel::EC.new(JSON.parse(token.to_json))

    expect do
      p.decrypt(
        merchant_id: merchant.merchant_id,
        private_key: merchant.key,
        certificate: merchant.certificate,
        now: Time.now - Pedicel.config[:replay_threshold_seconds] - 1
      )
    end.to raise_error(Pedicel::SignatureError)
  end

  it 'fails with bad encryption algorithms' do
    pending('Awaiting implementation')
    fail
  end
end

describe 'pedicel' do
  context 'signature' do
    it 'validates successful signature' do
      backend, _, token = PedicelPay::Helper.generate_all

      # Overwrite default CA in pedicel.
      Pedicel.config =
        Pedicel::DEFAULTS.merge(
          apple_root_ca_g3_cert_pem: backend.ca_certificate.to_pem
        ).freeze

      p = Pedicel::EC.new(JSON.parse(token.to_json))

      expect(p.valid_signature?).to be true
    end

    it 'does not validate invalid signature' do
      backend, _, token = PedicelPay::Helper.generate_all(
        pp_config: PedicelPay.config.merge(
          sign_token: false
        )
      )

      fake_backend, = PedicelPay::Helper.generate_all
      fake_backend.sign(
        token,
        fake_backend.leaf_certificate,
        fake_backend.leaf_key
      )

      Pedicel.config =
        Pedicel::DEFAULTS.merge(
          apple_root_ca_g3_cert_pem: backend.ca_certificate.to_pem
        ).freeze

      p = Pedicel::EC.new(JSON.parse(token.to_json))

      expect(p.valid_signature?).to be false
    end

    it 'does not validate doubly signed signature' do
      backend, _, token = PedicelPay::Helper.generate_all

      fake_backend, = PedicelPay::Helper.generate_all
      fake_backend.sign(
        token,
        fake_backend.leaf_certificate,
        fake_backend.leaf_key
      )

      Pedicel.config =
        Pedicel::DEFAULTS.merge(
          apple_root_ca_g3_cert_pem: backend.ca_certificate.to_pem
        ).freeze

      p = Pedicel::EC.new(JSON.parse(token.to_json))

      expect(p.valid_signature?).to be false
    end

    it 'does not validate signature of different data' do
      backend, _, token = PedicelPay::Helper.generate_all(
        pp_config: PedicelPay.config.merge(
          sign_token: false
        )
      )

      trx_id = token.header.transaction_id
      token.header.transaction_id = Random.new.bytes(44)

      backend.sign(
        token,
        backend.leaf_certificate,
        backend.leaf_key
      )

      token.header.transaction_id = trx_id

      Pedicel.config =
        Pedicel::DEFAULTS.merge(
          apple_root_ca_g3_cert_pem: backend.ca_certificate.to_pem
        ).freeze

      p = Pedicel::EC.new(JSON.parse(token.to_json))

      expect(p.valid_signature?).to be false
    end
  end
end
