require 'pedicel/base'
require 'pedicel-pay'

describe 'Pedicel::Base' do
  let (:backend) { PedicelPay::Backend.generate }

  let (:client) { backend.generate_client }

  let (:token) { PedicelPay::Token.new.sample }

  let (:config) { Pedicel::DEFAULT_CONFIG.merge(trusted_ca_pem: backend.ca_certificate.to_pem) }

  let (:pedicel) do
    backend.encrypt_and_sign(token, recipient: client)

    Pedicel::EC.new(token.to_hash, config: config)
  end

  describe 'basic accessors' do
    it '#version extracts the version as a symbol' do
      expect(pedicel.version).to eq(token.version.to_sym)
    end

    it '#encrypted_data extracts the raw encrypted data' do
      expect(pedicel.encrypted_data).to eq(token.encrypted_data)
    end

    it '#signature extracts the raw signature' do
      expect(pedicel.signature).to eq(Base64.decode64(token.signature))
    end

    it '#transaction_id extracts the raw transactionId' do
      expect(pedicel.transaction_id).to eq(token.header.transaction_id)
    end

    it '#application_data extracts the raw applicationData' do
      expect(pedicel.application_data).to eq(token.header.data_hash)
    end

    it "#private_key_class returns the private key's class" do
      expect(pedicel.private_key_class).to eq(OpenSSL::PKey::EC)
    end

    it "#symmetric_algorithm returns the identifier for the symmetric encryption algorithm to be used" do
      expect(pedicel.symmetric_algorithm).to eq('aes-256-gcm')
    end
  end

  describe '#decrypt_aes' do
    let(:unencrypted_data) { 'unencrypted data' }
    let(:key) { OpenSSL::Digest::SHA256.new.update('key').digest }

    let(:token_hash) do
      backend.encrypt_and_sign(token, recipient: client)
      JSON.parse(token.to_json, symbolize_names: true)
    end

    it 'decrypts with the correct key' do
      token_hash.merge!(data: Base64.encode64(PedicelPay::Helper.encrypt(data: unencrypted_data, key: key)))

      expect(Pedicel::Validator::Token).to receive(:new).and_return(double(validate: true, output: token_hash))
      expect(Pedicel::Base.new(:anything).decrypt_aes(key: key)).to eq(unencrypted_data)
    end

    it 'errs when the wrong key is given' do
      wrong_key = OpenSSL::Digest::SHA256.new.update('wrong key').digest

      token_hash.merge!(data: Base64.encode64(PedicelPay::Helper.encrypt(data: unencrypted_data, key: key)))

      expect(Pedicel::Validator::Token).to receive(:new).twice.and_return(double(validate: true, output: token_hash))
      expect(Pedicel::Base.new(:anything).decrypt_aes(key: key)).to eq(unencrypted_data)
      expect{Pedicel::Base.new(:anything).decrypt_aes(key: wrong_key)}.to raise_error(Pedicel::AesKeyError)
    end

    it 'errs when an invalid key is given' do
      invalid_key = 'invalid key' # Invalid length; should be 32 bytes.

      expect(Pedicel::Validator::Token).to receive(:new).and_return(double(validate: true, output: token_hash))
      expect{Pedicel::Base.new(:anything).decrypt_aes(key: invalid_key)}.to raise_error(Pedicel::AesKeyError)
    end
  end

  describe '#valid_signature?' do
    it 'is true when verify_signature is truthy' do
      expect(pedicel).to receive(:verify_signature).and_return(pedicel)

      expect(pedicel.valid_signature?).to be true
    end

    it 'is false when verify_signature is falsey' do
      expect(pedicel).to receive(:verify_signature).and_return(nil)

      expect(pedicel.valid_signature?).to be false
    end

    it 'is false when verify_signature raises an error' do
      expect(pedicel).to receive(:verify_signature).and_raise(Pedicel::SignatureError, 'boom')

      expect(pedicel.valid_signature?).to be false
    end
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

        expect(Pedicel::Validator::Token).to receive(:new).and_return(double(validate: true, output: JSON.parse(token.to_json, symbolize_names: true)))
        pedicel = Pedicel::EC.new(:anything)

        expect{pedicel.verify_signature}.to raise_error(Pedicel::SignatureError, /no signature/)
      end

      it 'errs on invalid signature' do
        backend.encrypt_and_sign(token, recipient: client)
        token.signature = 'invalid signature'

        expect(Pedicel::Validator::Token).to receive(:new).and_return(double(validate: true, output: JSON.parse(token.to_json, symbolize_names: true)))
        pedicel = Pedicel::EC.new(:anything)

        expect{pedicel.verify_signature}.to raise_error(Pedicel::SignatureError, /invalid PKCS/)
      end
    end

    context 'other checks' do
      it 'is truthy when all checks are good' do
        expect(pedicel.verify_signature).to be_truthy
      end

      it "uses the config's :trusted_ca_pem" do
        backend # Have the certificates created first.

        expect(Pedicel::Base).to receive(:verify_root_certificate).with(hash_including(trusted_root: backend.ca_certificate))

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

    context 'errors' do
      subject do
        lambda do
          Pedicel::Base.extract_certificates(signature: signature,
                                             intermediate_oid: pedicel.config[:oid_intermediate_certificate],
                                             leaf_oid: pedicel.config[:oid_leaf_certificate])
        end
      end

      it 'does not err when all checks are good' do
        is_expected.to_not raise_error
      end

      it 'errs if there is no leaf OID' do
        pedicel.config.merge!(oid_leaf_certificate: 'invalid oid')

        is_expected.to raise_error(Pedicel::SignatureError, /no.*leaf.*found/)
      end

      it 'errs if there is no intermediate OID' do
        pedicel.config.merge!(oid_intermediate_certificate: 'invalid oid')

        is_expected.to raise_error(Pedicel::SignatureError, /no.*intermediate.*found/)
      end

      it 'errs if there are neither a leaf nor an intermediate OID' do
        pedicel.config.merge!(oid_leaf_certificate: 'invalid oid')
        pedicel.config.merge!(oid_intermediate_certificate: 'invalid oid')

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

      it 'handles that one certificate can be both intermediate and leaf' do
        def create_special_certificate(ca_key, ca_certificate, config, oids)
          key = OpenSSL::PKey::EC.new(PedicelPay::EC_CURVE)
          key.generate_key

          cert = OpenSSL::X509::Certificate.new
          # https://www.ietf.org/rfc/rfc5280.txt -> Section 4.1, search for "v3(2)".
          cert.version = 2
          cert.serial = 1
          cert.subject = config[:subject][:intermediate]
          cert.issuer = ca_certificate.subject
          cert.public_key = PedicelPay::Helper.ec_key_to_pkey_public_key(key)
          cert.not_before = config[:valid].min
          cert.not_after = config[:valid].max

          ef = OpenSSL::X509::ExtensionFactory.new
          ef.subject_certificate = cert
          ef.issuer_certificate = ca_certificate

          # According to https://tools.ietf.org/html/rfc5280#section-4.2.1.9,
          # CA:TRUE must be set in order to allow signing using this
          # intermediate certificate.
          cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))

          cert.add_extension(ef.create_extension('keyUsage', 'keyCertSign, cRLSign', true))
          cert.add_extension(ef.create_extension('subjectKeyIdentifier', 'hash', false))

          oids.each do |oid|
            cert.add_extension(OpenSSL::X509::Extension.new(oid, ''))
          end

          cert.sign(ca_key, OpenSSL::Digest::SHA256.new)

          [key, cert]
        end

        c = PedicelPay.config
        oids = [ c[:oid][:intermediate_certificate], c[:oid][:leaf_certificate] ]
        backend.leaf_key, backend.leaf_certificate = create_special_certificate(backend.ca_key, backend.ca_certificate, c, oids)

        expect(backend).to receive(:sign) do |token|
          message = [
            PedicelPay::Helper.ec_key_to_pkey_public_key(token.header.ephemeral_pubkey).to_der,
            token.encrypted_data,
            token.header.transaction_id,
            token.header.data_hash
          ].compact.join

          signature = OpenSSL::PKCS7.sign(
            backend.leaf_certificate,
            backend.leaf_key,
            message,
            [backend.ca_certificate], # NOTICE! No intermediate in the chain!
            OpenSSL::PKCS7::BINARY # Handle 0x00 correctly.
          )

          token.signature = Base64.strict_encode64(signature.to_der)

          token
        end

        signature = OpenSSL::PKCS7.new(pedicel.signature)

        expect(Pedicel::Base.extract_certificates(signature: signature)).to eq([backend.leaf_certificate, backend.leaf_certificate, backend.ca_certificate])
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

      expect{Pedicel::Base.extract_certificates(signature: signature)}.to raise_error(Pedicel::SignatureError, /\Atoo many certificates found in the signature:/)
    end
  end

  describe 'Pedicel::Base.verify_root_certificate' do
    it 'errs when the certificates differ' do
      expect{Pedicel::Base.verify_root_certificate(root: backend.ca_certificate, trusted_root: PedicelPay::Backend.generate.ca_certificate)}.to raise_error(Pedicel::SignatureError, /root.*not trusted/)
    end

    it 'does not err when the certificates are equal' do
      expect{Pedicel::Base.verify_root_certificate(root: backend.ca_certificate, trusted_root: backend.ca_certificate)}.to_not raise_error
    end

    it 'is true when the certificates are equal' do
      expect(Pedicel::Base.verify_root_certificate(root: backend.ca_certificate, trusted_root: backend.ca_certificate)).to be true
    end
  end

  describe 'Pedicel::Base.verify_x509_chain' do
    let (:params) do
      {
        root:         backend.ca_certificate,
        intermediate: backend.intermediate_certificate,
        leaf:         backend.leaf_certificate,
      }
    end

    it 'does not err when the chain is good' do
      expect{Pedicel::Base.verify_x509_chain(params)}.to_not raise_error
    end

    context 'intermediate equals leaf' do
      it 'errs if intermediate = leaf (because root did not sign leaf)' do
        params[:intermediate] = params[:leaf]
        expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to intermediate')
      end

      it 'errs even if intermediate = leaf is self-signed' do
        params[:intermediate] = params[:leaf] = PedicelPay::Backend.generate.ca_certificate
        expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to intermediate')
      end
    end

    context 'leaf equals intermediate' do
      it 'errs if leaf = intermediate (because intermediate did not sign leaf)' do
        params[:leaf] = params[:intermediate]
        expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to leaf')
      end

      it 'errs even if leaf = intermediate is self-signed' do
        params[:leaf] = params[:intermediate] = PedicelPay::Backend.generate.ca_certificate
        expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to intermediate')
      end
    end

    it 'errs if intermediate equals root (because root did not sign leaf)' do
      params[:intermediate] = params[:root]
      expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to leaf')
    end

    it 'errs if root equals intermediate (because intermediate is not self-signed)' do
      params[:root] = params[:intermediate]
      expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to root')
    end

    it 'errs if leaf equals root (because intermediate did not sign leaf)' do
      params[:leaf] = params[:root]
      expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to leaf')
    end

    it 'errs if root equals leaf (becuase leaf is not self-signed)' do
      params[:root] = params[:leaf]
      expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to root')
    end

    it 'errs if leaf is used for all 3 certificates (because of multiple reasons)' do
      params[:root]         = params[:leaf]
      params[:intermediate] = params[:leaf]
      expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to root')
    end

    it 'errs if intermediate is used for all 3 certificates' do
      params[:root] = params[:intermediate]
      params[:leaf] = params[:intermediate]
      expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to root')
    end

    it 'does not err when root is used for all 3 certificates' do
      params[:intermediate] = params[:root]
      params[:leaf]         = params[:root]
      expect{Pedicel::Base.verify_x509_chain(params)}.to_not raise_error
    end

    it 'errs if intermediate is not signed by root' do
      params[:root] = PedicelPay::Backend.generate.ca_certificate

      expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to intermediate')
    end

    it 'errs if leaf is not signed by intermediate (1)' do
      params[:leaf] = PedicelPay::Backend.generate.leaf_certificate

      expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to leaf')
    end

    it 'errs if leaf is not signed by intermediate (2)' do
      another_backend = PedicelPay::Backend.generate
      params[:root]         = another_backend.ca_certificate
      params[:intermediate] = another_backend.intermediate_certificate

      expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to leaf')
    end

    it 'errs if leaf is not signed by intermediate and intermediate is not signed by root' do
      params[:root]         = PedicelPay::Backend.generate.ca_certificate
      params[:intermediate] = PedicelPay::Backend.generate.intermediate_certificate

      expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to intermediate')
    end

    it 'errs if certs are interchanged' do
      params.keys.permutation.reject{|ks| ks == params.keys}.each do |permutated_keys|
        permutated_params = permutated_keys.zip(params.values).to_h

        expect{Pedicel::Base.verify_x509_chain(permutated_params)}.to raise_error(Pedicel::SignatureError, /\Ainvalid chain due to (root|intermediate|leaf)\z/)
      end
    end

    it 'errs even if the leaf is self-signed' do
      params[:leaf] = PedicelPay::Backend.generate.ca_certificate
      expect{Pedicel::Base.verify_x509_chain(params)}.to raise_error(Pedicel::SignatureError, 'invalid chain due to leaf')
    end

    it 'is true when the chain is good' do
      expect(Pedicel::Base.verify_x509_chain(params)).to be true
    end
  end


  describe 'Pedicel::Base.verify_signed_time' do
    let (:signature) { OpenSSL::PKCS7.new(pedicel.signature) }
    let (:now) { signature.signers.first.signed_time }

    it 'does not err when all checks are good' do
      expect{Pedicel::Base.verify_signed_time(signature: signature, now: now)}.to_not raise_error
    end

    let (:limit) { pedicel.config[:replay_threshold_seconds] }

    it 'errs if the signature has multiple signers' do
      backend.encrypt_and_sign(token, recipient: client)
      PedicelPay::Backend.generate.sign(token, replace: false)
      signature = OpenSSL::PKCS7.new(Pedicel::EC.new(token.to_hash, config: config).signature)
      expect{Pedicel::Base.verify_signed_time(signature: signature, now: now)}.to raise_error(Pedicel::SignatureError, 'not 1 signer, unable to determine signing time')
    end

    it 'errs if the signature is too new' do
      expect{Pedicel::Base.verify_signed_time(signature: signature, now: now-limit)}.to_not raise_error
      expect{Pedicel::Base.verify_signed_time(signature: signature, now: now-limit-1)}.to raise_error(Pedicel::SignatureError)
    end

    it 'errs if the signature is too old' do
      expect{Pedicel::Base.verify_signed_time(signature: signature, now: now+limit)}.to_not raise_error
      expect{Pedicel::Base.verify_signed_time(signature: signature, now: now+limit+1)}.to raise_error(Pedicel::SignatureError)
    end

    it 'is true when all checks are good' do
      expect(Pedicel::Base.verify_signed_time(signature: signature, now: now)).to be true
    end
  end
end
