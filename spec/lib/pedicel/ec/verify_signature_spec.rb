require 'pedicel/ec'
require 'pedicel-pay'

describe 'Pedicel::EC#verify_signature' do
  describe 'checks all necessary parts' do
    let (:backend) { PedicelPay::Backend.generate }
    let (:client) { backend.generate_client }
    let (:token) { PedicelPay::Token.new.sample }

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
      let (:pedicel) do
        backend.encrypt_and_sign(token, recipient: client)
        Pedicel.config.merge!(trusted_ca_pem: backend.ca_certificate.to_pem)

        Pedicel::EC.new(token.to_hash)
      end

      after (:all) { Pedicel.config.merge!(trusted_ca_pem: Pedicel::APPLE_ROOT_CA_G3_CERT_PEM) }

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
end
