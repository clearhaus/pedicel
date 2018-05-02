require 'pedicel/ec'
require 'pedicel-pay'

describe 'Signature verification' do
  let (:backend) do
    backend = PedicelPay::Backend.generate
    Pedicel.config.merge!(trusted_ca_pem: backend.ca_certificate.to_pem)

    backend
  end

  after (:all) { Pedicel.config.merge!(trusted_ca_pem: Pedicel::APPLE_ROOT_CA_G3_CERT_PEM) }

  let (:client) { backend.generate_client }

  let (:token) { PedicelPay::Token.new.sample }

  let (:pedicel) do
    backend.encrypt_and_sign(token, recipient: client)

    Pedicel::EC.new(token.to_hash)
  end

  describe 'Pedicel::EC#validate_signature' do
    let (:signature) { OpenSSL::PKCS7.new(pedicel.signature) }

    # Test private method.
    before (:all) { Pedicel::EC.class_eval { public  :validate_signature } }
    after  (:all) { Pedicel::EC.class_eval { private :validate_signature } }

    it 'does not err when the signature is good' do
      expect{pedicel.validate_signature(signature: signature, leaf: backend.leaf_certificate)}.to_not raise_error
    end

    it 'errs if transaction_id has been changed' do
      backend.encrypt_and_sign(token, recipient: client)
      token.header.transaction_id = 'another_value'
      pedicel = Pedicel::EC.new(token.to_hash)

      expect{pedicel.validate_signature(signature: signature, leaf: backend.leaf_certificate)}.to raise_error(Pedicel::SignatureError, /signature.*not match.* message/)
    end

    it 'errs if ephemeral_public_key has been changed' do
      backend.encrypt_and_sign(token, recipient: client)
      _, token.header.ephemeral_pubkey = PedicelPay::Backend.generate_shared_secret_and_ephemeral_pubkey(recipient: client)
      pedicel = Pedicel::EC.new(token.to_hash)

      expect{pedicel.validate_signature(signature: signature, leaf: backend.leaf_certificate)}.to raise_error(Pedicel::SignatureError, /signature.*not match.* message/)
    end

    it 'errs if encrypted_data has been changed' do
      backend.encrypt_and_sign(token, recipient: client)
      token.encrypted_data += '0'.chr
      pedicel = Pedicel::EC.new(token.to_hash)

      expect{pedicel.validate_signature(signature: signature, leaf: backend.leaf_certificate)}.to raise_error(Pedicel::SignatureError, /signature.*not match.* message/)
    end

    it 'errs if application_data has been changed' do
      backend.encrypt_and_sign(token, recipient: client)
      token.header.data_hash = OpenSSL::Digest::SHA256.new('foobar').digest
      pedicel = Pedicel::EC.new(token.to_hash)

      expect{pedicel.validate_signature(signature: signature, leaf: backend.leaf_certificate)}.to raise_error(Pedicel::SignatureError, /signature.*not match.* message/)
    end

    it 'errs if the signature algorithm is not ecdsa-with-SHA256' do
      expect(OpenSSL::Digest::SHA256).to receive(:new).and_return(OpenSSL::Digest::SHA512.new).at_least(:once)

      expect{pedicel.validate_signature(signature: signature, leaf: backend.leaf_certificate)}.to raise_error(Pedicel::SignatureError, 'signature algorithm is not ecdsa-with-SHA256')
    end

    it 'is truthy when the signature is good' do
      expect(pedicel.validate_signature(signature: signature, leaf: backend.leaf_certificate)).to be_truthy
    end
  end
end
