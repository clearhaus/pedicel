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

  describe 'Pedicel::Base.verify_signature' do
    context 'checks specified by Apple' do
      subject { lambda { pedicel.verify_signature } }

      it 'does not err when all checks are good' do
        is_expected.to_not raise_error
      end

      it 'checks for the custom OIDs (1.a)' do
        expect(Pedicel::Base).to receive(:extract_certificates).and_raise(Pedicel::SignatureError, 'boom')

        is_expected.to raise_error(Pedicel::SignatureError, 'boom')
      end

      it 'checks that the root certificate is trusted (1.b)' do
        expect(Pedicel::Base).to receive(:verify_root_certificate).and_raise(Pedicel::SignatureError, 'boom')

        is_expected.to raise_error(Pedicel::SignatureError, 'boom')
      end

      it 'checks the chain (1.c)' do
        expect(Pedicel::Base).to receive(:verify_x509_chain).and_raise(Pedicel::SignatureError, 'boom')

        is_expected.to raise_error(Pedicel::SignatureError, 'boom')
      end

      it "checks the token's signature (1.d)" do
        expect(pedicel).to receive(:validate_signature).and_raise(Pedicel::SignatureError, 'boom')

        is_expected.to raise_error(Pedicel::SignatureError, 'boom')
      end

      it 'checks signing time (1.e)' do
        expect(Pedicel::Base).to receive(:verify_signed_time).and_raise(Pedicel::SignatureError, 'boom')

        is_expected.to raise_error(Pedicel::SignatureError, 'boom')
      end
    end

    context 'basic signature checks' do
      it 'errs on missing signature' do
        backend.encrypt_and_sign(token, recipient: client)
        token.signature = nil

        pedicel = Pedicel::EC.new(token.to_hash)

        expect{pedicel.verify_signature}.to raise_error(Pedicel::SignatureError, /no signature/)
      end

      it 'errs on invalid signature' do
        backend.encrypt_and_sign(token, recipient: client)
        token.signature = 'invalid signature'

        pedicel = Pedicel::EC.new(token.to_hash)

        expect{pedicel.verify_signature}.to raise_error(Pedicel::SignatureError, /invalid PKCS/)
      end
    end

    context 'other checks' do
      it 'is truthy when all checks are good' do
        expect(pedicel.verify_signature).to be_truthy
      end

      it "uses the config's :trusted_ca_pem" do
        root = backend.ca_certificate
        trusted_root = OpenSSL::X509::Certificate.new(Pedicel.config[:trusted_ca_pem])
        expect(Pedicel::Base).to receive(:verify_root_certificate).with({trusted_root: trusted_root, root: root})

        pedicel.verify_signature
      end

      it 'sends the leaf to #validate_signature' do
        expect(pedicel).to receive(:validate_signature) do |params|
          fail 'wrong leaf' unless params[:leaf] == backend.leaf_certificate
        end

        expect{pedicel.verify_signature}.to_not raise_error
      end
    end
  end

  describe 'Pedicel::Base.extract_certificates' do
    let (:signature) { OpenSSL::PKCS7.new(pedicel.signature) }

    before (:each) { Pedicel.config.merge!(trusted_ca_pem: backend.ca_certificate.to_pem) }
    after  (:each) { Pedicel.reset_config }

    context 'errors' do
      subject { lambda { Pedicel::Base.extract_certificates(signature: signature) } }

      it 'does not err when all checks are good' do
        is_expected.to_not raise_error
      end

      it 'errs if there is no leaf OID' do
        Pedicel.config[:oids][:leaf_certificate] = 'invalid oid'

        is_expected.to raise_error(Pedicel::SignatureError, /no.*leaf.*found/)
      end

      it 'errs if there is no intermediate OID' do
        Pedicel.config[:oids][:intermediate_certificate] = 'invalid oid'

        is_expected.to raise_error(Pedicel::SignatureError, /no.*intermediate.*found/)
      end

      it 'errs if there are neither a leaf nor an intermediate OID' do
        Pedicel.config[:oids][:leaf_certificate] = 'invalid oid'
        Pedicel.config[:oids][:intermediate_certificate] = 'invalid oid'

        is_expected.to raise_error(Pedicel::SignatureError, /no.*(leaf|intermediate).*found/)
      end
    end

    context 'values' do
      subject { Pedicel::Base.extract_certificates(signature: signature) }

      it 'is truthy when all checks are good' do
        is_expected.to be_truthy
      end

      it 'extracts leaf, intermediate, and root' do
        is_expected.to eq([backend.leaf_certificate, backend.intermediate_certificate, backend.ca_certificate])
      end
    end
  end

  describe 'Pedicel::Base.extract_certificates' do
    before (:each) { backend.encrypt_and_sign(token, recipient: client) }

    let (:another_backend) { PedicelPay::Backend.generate }

    let (:signature) { OpenSSL::PKCS7.new(Base64.strict_decode64(token.signature)) }

    it 'errs if there are multiple leaf OIDs' do
      signature.add_certificate(another_backend.leaf_certificate)

      expect{Pedicel::Base.extract_certificates(signature: signature)}.to raise_error(Pedicel::SignatureError, /no unique leaf/)
    end

    it 'errs if there are multiple intermediate OIDs' do
      signature.add_certificate(another_backend.intermediate_certificate)

      expect{Pedicel::Base.extract_certificates(signature: signature)}.to raise_error(Pedicel::SignatureError, /no unique intermediate/)
    end

    it 'errs if there are multiple leaf and intermediate OIDs' do
      signature.add_certificate(another_backend.leaf_certificate)
      signature.add_certificate(another_backend.intermediate_certificate)

      expect{Pedicel::Base.extract_certificates(signature: signature)}.to raise_error(Pedicel::SignatureError, /no unique (leaf|intermediate)/)
    end

    it 'errs if there are multiple certificates that are neither leaf nor intermediate' do
      signature.add_certificate(another_backend.ca_certificate)

      expect{Pedicel::Base.extract_certificates(signature: signature)}.to raise_error(Pedicel::SignatureError, /no unique root/)
    end
  end

  describe 'Pedicel::Base.verify_root_certificate' do
    it 'does not err when the certificates are equal' do
      expect{Pedicel::Base.verify_root_certificate(root: backend.ca_certificate, trusted_root: PedicelPay::Backend.generate.ca_certificate)}.to raise_error(Pedicel::SignatureError, /root.*not trusted/)
    end

    it 'is truthy when the certificates are equal' do
      expect(Pedicel::Base.verify_root_certificate(root: backend.ca_certificate, trusted_root: backend.ca_certificate)).to be_truthy
    end
  end

  describe 'Pedicel::Base.verify_x509_chain' do
    let (:params) do
      {
        root: backend.ca_certificate,
        intermediate: backend.intermediate_certificate,
        leaf: backend.leaf_certificate,
      }
    end

    it 'does not err when the chain is good' do
      expect{Pedicel::Base.verify_x509_chain(params)}.to_not raise_error
    end

    it 'is truthy when the chain is good' do
      expect(Pedicel::Base.verify_x509_chain(params)).to be_truthy
    end

    it 'errs if certs are interchanged' do
      params.keys.permutation.reject{|ks| ks == params.keys}.each do |permutated_keys|
        permutated_params = permutated_keys.zip(params.values).to_h

        expect{Pedicel::Base.verify_x509_chain(permutated_params)}.to raise_error(Pedicel::SignatureError, /(did not sign|is( not)? self-signed)/)
      end
    end

    it 'errs if any 2 certificates are equal' do
      params.keys.permutation(2) do |one, another|
        mangled_params = params.dup
        mangled_params[one] = mangled_params[another]

        expect{Pedicel::Base.verify_x509_chain(mangled_params)}.to raise_error(Pedicel::SignatureError, /(did not sign|is( not)? self-signed)/)
      end
    end

    it 'errs if all 3 certificates are equal' do
      params.values.each do |value|
        expect{Pedicel::Base.verify_x509_chain(root: value, intermediate: value, leaf: value)}.to raise_error(Pedicel::SignatureError, /is( not)? self-signed/)
      end
    end
  end

  describe 'Pedicel::EC#validate_signature' do
    it 'works'

    let (:signature) { OpenSSL::PKCS7.new(pedicel.signature) }

    it 'does not err when the signature is good' do
      expect{pedicel.send(:validate_signature, {signature: signature, leaf: backend.leaf_certificate})}.to_not raise_error
    end

    it 'errs if transaction_id has been changed' do
      backend.encrypt_and_sign(token, recipient: client)
      token.header.transaction_id = 'another_value'
      pedicel = Pedicel::EC.new(token.to_hash)

      expect{pedicel.send(:validate_signature, {signature: signature, leaf: backend.leaf_certificate})}.to raise_error(Pedicel::SignatureError, /signature.*not match.* message/)
    end

    it 'errs if ephemeral_public_key has been changed' do
      backend.encrypt_and_sign(token, recipient: client)
      _, token.header.ephemeral_pubkey = PedicelPay::Backend.generate_shared_secret_and_ephemeral_pubkey(recipient: client)
      pedicel = Pedicel::EC.new(token.to_hash)

      expect{pedicel.send(:validate_signature, {signature: signature, leaf: backend.leaf_certificate})}.to raise_error(Pedicel::SignatureError, /signature.*not match.* message/)
    end

    it 'errs if encrypted_data has been changed' do
      backend.encrypt_and_sign(token, recipient: client)
      token.encrypted_data += '0'.chr
      pedicel = Pedicel::EC.new(token.to_hash)

      expect{pedicel.send(:validate_signature, {signature: signature, leaf: backend.leaf_certificate})}.to raise_error(Pedicel::SignatureError, /signature.*not match.* message/)
    end

    it 'errs if application_data has been changed' do
      backend.encrypt_and_sign(token, recipient: client)
      token.header.data_hash = OpenSSL::Digest::SHA256.new('foobar').digest
      pedicel = Pedicel::EC.new(token.to_hash)

      expect{pedicel.send(:validate_signature, {signature: signature, leaf: backend.leaf_certificate})}.to raise_error(Pedicel::SignatureError, /signature.*not match.* message/)
    end
  end

  describe 'Pedicel::Base.verify_signed_time' do
    let (:signature) { OpenSSL::PKCS7.new(pedicel.signature) }
    let (:now) { signature.signers.first.signed_time }

    it 'does not err when all checks are good' do
      expect{Pedicel::Base.verify_signed_time(signature: signature, now: now)}.to_not raise_error
    end

    let (:limit) { Pedicel.config[:replay_threshold_seconds] }

    it 'errs if the signature is too new' do
      expect{Pedicel::Base.verify_signed_time(signature: signature, now: now-limit)}.to_not raise_error
      expect{Pedicel::Base.verify_signed_time(signature: signature, now: now-limit-1)}.to raise_error(Pedicel::SignatureError)
    end

    it 'errs if the signature is too old' do
      expect{Pedicel::Base.verify_signed_time(signature: signature, now: now+limit)}.to_not raise_error
      expect{Pedicel::Base.verify_signed_time(signature: signature, now: now+limit+1)}.to raise_error(Pedicel::SignatureError)
    end

    it 'is truthy when all checks are good' do
      expect(Pedicel::Base.verify_signed_time(signature: signature, now: now)).to be_truthy
    end
  end
end
