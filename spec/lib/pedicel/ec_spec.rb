require 'pedicel/ec'
require 'pedicel-pay'

describe 'Pedicel::EC' do
  let (:backend) { PedicelPay::Backend.generate }

  let (:client) { backend.generate_client }

  let (:token) { PedicelPay::Token.new.sample }

  let (:pedicel) do
    backend.encrypt_and_sign(token, recipient: client)

    config = Pedicel::DEFAULT_CONFIG.merge(trusted_ca_pem: backend.ca_certificate.to_pem)

    Pedicel::EC.new(token.to_hash, config: config)
  end

  describe '#decrypt' do
    it 'decrypts using the symmetric key' do
      ss, epk = PedicelPay::Backend.generate_shared_secret_and_ephemeral_pubkey(recipient: client)

      backend.encrypt_and_sign(token, recipient: client, shared_secret: ss, ephemeral_pubkey: epk)

      pedicel = Pedicel::EC.new(token.to_hash)
      pedicel.config = Pedicel::DEFAULT_CONFIG.merge(trusted_ca_pem: backend.ca_certificate.to_pem)

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

  describe '#symmetric_key' do
    let (:ss_and_epk) { @x ||= PedicelPay::Backend.generate_shared_secret_and_ephemeral_pubkey(recipient: client) }
    let (:ss) { ss_and_epk.first }
    let (:epk) { ss_and_epk.last }

    let (:symmetric_key) do
      Pedicel::EC.symmetric_key(shared_secret: ss, merchant_id: Pedicel::EC.merchant_id(certificate: client.certificate))
    end

    let (:pedicel) do
      backend.encrypt_and_sign(token, recipient: client, shared_secret: ss, ephemeral_pubkey: epk)

      Pedicel::EC.new(token.to_hash)
    end

    it 'extracts the symmetric key using the private key and certificate' do
      expect(pedicel.symmetric_key(private_key: client.key, certificate: client.certificate)).to eq(symmetric_key)
    end

    it 'extracts the symmetric key using the private key and merchant id' do
      expect(pedicel.symmetric_key(private_key: client.key, merchant_id: client.merchant_id)).to eq(symmetric_key)
    end

    it 'errs when missing parameters' do
      expect{pedicel.decrypt(shared_secret: 'foo')}.to raise_error(ArgumentError)
      expect{pedicel.decrypt(private_key: 'foo')}.to raise_error(ArgumentError)
      expect{pedicel.decrypt(certificate: 'foo')}.to raise_error(ArgumentError)
      expect{pedicel.decrypt(merchant_id: 'foo')}.to raise_error(ArgumentError)
    end

    it 'errs when both shared_secret and private_key is supplied' do
      expect{pedicel.decrypt(shared_secret: 'foo', private_key: 'bar')}.to raise_error(ArgumentError)
    end

    it 'errs when both certificate and merchant_id is supplied' do
      expect{pedicel.decrypt(certificate: 'foo', merchant_id: 'bar')}.to raise_error(ArgumentError)
    end
  end

  describe '#shared_secret' do
    let (:ss_and_epk) { @x ||= PedicelPay::Backend.generate_shared_secret_and_ephemeral_pubkey(recipient: client) }
    let (:ss) { ss_and_epk.first }
    let (:epk) { ss_and_epk.last }

    let (:pedicel) do
      backend.encrypt_and_sign(token, recipient: client, shared_secret: ss, ephemeral_pubkey: epk)

      Pedicel::EC.new(token.to_hash)
    end

    it 'extracts the shared secret' do
      expect(pedicel.shared_secret(private_key: client.key)).to eq(ss)
    end

    it "errs if the private key is from another curve than the token's ephemeral public key" do
      key = OpenSSL::PKey::EC.new('wap-wsg-idm-ecid-wtls1') # Apple, do never switch to this curve.
      key.generate_key

      expect{pedicel.shared_secret(private_key: key)}.to raise_error(Pedicel::EcKeyError, /curve.*differ/)
    end

    it 'returns the wrong shared secret if the ephemeral public key is wrong' do
      _, another_epk = PedicelPay::Backend.generate_shared_secret_and_ephemeral_pubkey(recipient: client)

      expect(pedicel).to receive(:ephemeral_public_key).and_return(PedicelPay::Helper.ec_key_to_pkey_public_key(another_epk).to_pem)

      expect(pedicel.shared_secret(private_key: client.key)).to_not eq(ss)
    end

    it 'errs if the ephemeral public key is malformatted' do
      expect(pedicel).to receive(:ephemeral_public_key).and_return(Base64.decode64('An invalid ephemeral public key'))

      expect{pedicel.shared_secret(private_key: client.key)}.to raise_error(Pedicel::EcKeyError, /invalid ephemeralPublicKey/)
    end
  end

  describe '.symmetric_key' do
    let (:merchant_id) { "\x15\xDA25#2\x99uV\x94\xC6?,\xB9$\x98\x97}\xD9MI\x98\xA2R\xCCGOM\xAA\xF2\x7F\x1C" }
    let (:shared_secret) { "p)@\x89\x1E-\xA9\x8B`\x9C\xCE6((\xCB\x01\x8C\x17\x0F1\xE2?\xE1o\xA4\xEC&3\xCB\xEB9\xBF" }
    let (:symmetric_key) { "\xE2[\x8Bu\e\x9B\xF0\\\x9ET\xBAe\xBCA\x9A\xAC\x8F\n\x1DE8\xBE\xF1U&?\xDD\x8A\x1A\xCA\x1E\xA9".b }

    it 'computes the symmetric key correctly' do
      expect(Pedicel::EC.symmetric_key(merchant_id: merchant_id, shared_secret: shared_secret)).to eq(symmetric_key)
    end

    it 'errs on invalid merchant_id' do
      expect{Pedicel::EC.symmetric_key(merchant_id: nil, shared_secret: 'foo')}.to raise_error(ArgumentError, 'merchant_id must be a SHA256')
      expect{Pedicel::EC.symmetric_key(merchant_id: 'foo', shared_secret: 'foo')}.to raise_error(ArgumentError, 'merchant_id must be a SHA256')
    end

    it 'errs on invalid shared_secret' do
      expect{Pedicel::EC.symmetric_key(merchant_id: merchant_id, shared_secret: nil)}.to raise_error(ArgumentError, 'shared_secret must be a string')
    end
  end

  describe '.merchant_id' do
    let (:certificate) do
      OpenSSL::X509::Certificate.new <<~PEM
        -----BEGIN CERTIFICATE-----
        MIICezCCAiGgAwIBAgIBATAKBggqhkjOPQQDAjBtMQswCQYDVQQGEwJESzEVMBMG
        A1UECgwMUGVkaWNlbCBJbmMuMSgwJgYDVQQLDB9QZWRpY2VsIENlcnRpZmljYXRp
        b24gQXV0aG9yaXR5MR0wGwYDVQQDDBRQZWRpY2VsIFJvb3QgQ0EgLSBHMzAeFw0x
        NzAxMDEwMDAwMDBaFw0yMDAxMDEwMDAwMDBaMIHNMUEwPwYKCZImiZPyLGQBAQwx
        bWVyY2hhbnQtdXJsLnRsZC5wZWRpY2VsLW1lcmNoYW50LlBlZGljZWxNZXJjaGFu
        dDFHMEUGA1UEAww+TWVyY2hhbnQgSUQ6IG1lcmNoYW50LXVybC50bGQucGVkaWNl
        bC1tZXJjaGFudC5QZWRpY2VsTWVyY2hhbnQxEzARBgNVBAsMCjFXMlgzWTRaNUEx
        HTAbBgNVBAoMFFBlZGljZWxNZXJjaGFudCBJbmMuMQswCQYDVQQGEwJESzBZMBMG
        ByqGSM49AgEGCCqGSM49AwEHA0IABB+pgI+l0tNW1fUAtGsGA6M/URs58rR/pzXG
        7rsvGNLEFc1HkojZwo2P/whxlm6JYvRaxYXinS1mcbQi6NoR++2jUTBPME0GCSqG
        SIb3Y2QGIARAODdjYTY0ODM3ZjZjNjNkYzcwYTljNzViZjJlN2IxNGE1OGNkZWE2
        ZTI1Mjc1NDY0OTNlZmZiOWI3ZTMzMzM5MDAKBggqhkjOPQQDAgNIADBFAiAul5AI
        XUc8z4s9djNJCZkf8mOPRkNLOMPUsMoTdTxUQQIhALWDYnY3z4QRY778iVoDZNV3
        kSjBMc15dpFOBCoRYEJR
        -----END CERTIFICATE-----
        PEM
    end

    let(:merchant_id) { "\x87\xCAd\x83\x7Flc\xDCp\xA9\xC7[\xF2\xE7\xB1JX\xCD\xEAn%'Td\x93\xEF\xFB\x9B~33\x90".b }

    it 'extracts the merchant identifier correctly' do
      expect(Pedicel::EC.merchant_id(certificate: certificate)).to eq(merchant_id)
    end

    it 'errs on invalid certificate' do
      expect{Pedicel::EC.merchant_id(certificate: 'not PEM')}.to raise_error(Pedicel::CertificateError, /invalid PEM format/)
    end

    it 'errs if certificate has no merchant ID with the given OID' do
      config = { oid_merchant_identifier_field: 'wrong oid' }
      expect{Pedicel::EC.merchant_id(certificate: client.certificate, config: config)}.to raise_error(Pedicel::CertificateError, /no merchant identifier/)
    end
  end
end
