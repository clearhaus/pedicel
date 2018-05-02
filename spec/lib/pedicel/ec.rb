require 'pedicel/ec'
require 'pedicel-pay'

describe 'Pedicel::EC' do
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

  describe '#decrypt' do
    it 'decrypts using the symmetric key' do
      ss, ek = PedicelPay::Backend.generate_shared_secret_and_ephemeral_pubkey(recipient: client)

      backend.encrypt_and_sign(token, recipient: client, shared_secret: ss, ephemeral_pubkey: ek)

      pedicel = Pedicel::EC.new(token.to_hash)

      symmetric_key = Pedicel::EC.symmetric_key(
        shared_secret: ss,
        merchant_id: Pedicel::EC.merchant_id(certificate: client.certificate))

      expect(pedicel.decrypt(symmetric_key: symmetric_key)).to eq(token.unencrypted_data.to_json)
    end

    it 'decrypts using the certificate and private key' do
      expect(pedicel.decrypt(certificate: client.certificate, private_key: client.key)).to eq(token.unencrypted_data.to_json)
    end

    it 'decrypts using the merchant id and private key' do
      expect(pedicel.decrypt(merchant_id: client.merchant_id, private_key: client.key)).to eq(token.unencrypted_data.to_json)
    end

    it 'errs when missing parameters' do
      expect{pedicel.decrypt(private_key: 'foo')}.to raise_error(ArgumentError)
      expect{pedicel.decrypt(certificate: 'foo')}.to raise_error(ArgumentError)
      expect{pedicel.decrypt(merchant_id: 'foo')}.to raise_error(ArgumentError)
    end

    it 'errs when more than symmetric_key is supplied' do
      expect{pedicel.decrypt(symmetric_key: 'foo', merchant_id: 'bar')}.to raise_error(ArgumentError)
      expect{pedicel.decrypt(symmetric_key: 'foo', certificate: 'bar')}.to raise_error(ArgumentError)
      expect{pedicel.decrypt(symmetric_key: 'foo', private_key: 'bar')}.to raise_error(ArgumentError)
    end

    it 'errs when both certificate and merchant_id is supplied' do
      expect{pedicel.decrypt(certificate: 'foo', merchant_id: 'bar')}.to raise_error(ArgumentError)
    end

    it 'verifies the signature' do
      expect(pedicel).to receive(:verify_signature).and_return(true)
      expect(pedicel).to receive(:decrypt_aes).and_return('hest')

      expect(pedicel.decrypt(certificate: client.certificate, private_key: client.key)).to eq('hest')
    end

    it 'errs on invalid signature before attempting to decrypt' do
      expect(pedicel).to receive(:verify_signature).and_raise(Pedicel::SignatureError, 'boom')
      expect(pedicel).not_to receive(:decrypt_aes)

      expect{pedicel.decrypt(certificate: client.certificate, private_key: client.key)}.to raise_error(Pedicel::SignatureError, 'boom')
    end
  end

  describe '#validate_signature' do
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
