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

  describe 'Pedicel::EC#verify_signature' do
    context 'basic signature checks' do
      it 'errs on missing signature' do
        backend.encrypt_and_sign(token, recipient: client)
        token.signature = nil

        pedicel = Pedicel::EC.new(token.to_hash)

        expect{pedicel.verify_signature}.to raise_error(Pedicel::SignatureError)
      end

      it 'errs on invalid signature' do
        backend.encrypt_and_sign(token, recipient: client)
        token.signature = 'invalid signature'

        pedicel = Pedicel::EC.new(token.to_hash)

        expect{pedicel.verify_signature}.to raise_error(Pedicel::SignatureError)
      end
    end

    context 'checks specified by Apple' do
      it 'checks for the custom OIDs (1.a)' do
        expect(Pedicel::EC).to receive(:verify_signature_certificate_oids).and_raise(Pedicel::SignatureError, 'boom')

        expect{pedicel.verify_signature}.to raise_error(Pedicel::SignatureError, 'boom')
      end

      it 'checks that the root certificate is trusted (1.b)' do
        expect(Pedicel::EC).to receive(:verify_root_certificate).and_raise(Pedicel::SignatureError, 'boom')

        expect{pedicel.verify_signature}.to raise_error(Pedicel::SignatureError, 'boom')
      end

      it 'checks the chain (1.c)' do
        expect(Pedicel::EC).to receive(:verify_x509_chain).and_raise(Pedicel::SignatureError, 'boom')

        expect{pedicel.verify_signature}.to raise_error(Pedicel::SignatureError, 'boom')
      end

      it "checks the token's signature (1.d)" do
        expect(pedicel).to receive(:validate_signature).and_raise(Pedicel::SignatureError, 'boom')

        expect{pedicel.verify_signature}.to raise_error(Pedicel::SignatureError, 'boom')
      end

      it 'checks signing time (1.e)' do
        expect(Pedicel::EC).to receive(:verify_signed_time).and_raise(Pedicel::SignatureError, 'boom')

        expect{pedicel.verify_signature}.to raise_error(Pedicel::SignatureError, 'boom')
      end

      it 'does not err when all checks are good' do
        expect{pedicel.verify_signature}.to_not raise_error
      end

      it 'is truthy when all checks are good' do
        expect(pedicel.verify_signature).to be_truthy
      end
    end
  end

  describe 'Pedicel::EC#verify_signature_certificate_oids' do
    let (:signature) { OpenSSL::PKCS7.new(pedicel.signature) }

    subject { lambda { Pedicel::Base.verify_signature_certificate_oids(signature: signature) } }

    before (:each) { Pedicel.config.merge!(trusted_ca_pem: backend.ca_certificate.to_pem) }
    after  (:each) { Pedicel.reset_config }

    it 'errs if there is no leaf OID' do
      Pedicel.config[:oids][:leaf_certificate] = 'invalid oid'

      is_expected.to raise_error(Pedicel::SignatureError)
    end

    it 'errs if there is no intermediate OID' do
      Pedicel.config[:oids][:intermediate_certificate] = 'invalid oid'

      is_expected.to raise_error(Pedicel::SignatureError)
    end

    it 'errs if there are neither a leaf nor an intermediate OID' do
      Pedicel.config[:oids][:leaf_certificate] = 'invalid oid'
      Pedicel.config[:oids][:intermediate_certificate] = 'invalid oid'

      is_expected.to raise_error(Pedicel::SignatureError)
    end

    it 'errs if there are multiple leaf OIDs'

    it 'errs if there are multiple intermediate OIDs'

    it 'errs if there are multiple leaf and intermediate OIDs'

    it 'does not err when all checks are good' do
      is_expected.to_not raise_error
    end

    it 'is truthy when all checks are good' do
      is_expected.to be_truthy
    end
  end
end
