require 'securerandom'
require 'base64'

def ec_key_to_pkey_public_key(ec_key)
  # EC#public_key is not a PKey public key, but an EC point.
  pub = OpenSSL::PKey::EC.new(ec_key.group)
  pub.public_key = ec_key.is_a?(OpenSSL::PKey::PKey) ? ec_key.public_key : ec_key

  pub
end

module PedicelPay
  class Merchant
    def initialize
      @key = OpenSSL::PKey::EC.new('prime256v1')
      @key.generate_key
    end

    attr_reader :key

    def csr
      req = OpenSSL::X509::Request.new
      req.version = 0
      req.subject = OpenSSL::X509::Name.parse('/CN=merchant-url.tld')
      req.public_key = ec_key_to_pkey_public_key(@key)
      req.sign(@key, OpenSSL::Digest::SHA256.new)

      req
    end
  end

  class Token
    class Data
      def self.sample
        future = Time.now + 365*24*60*60
        new(application_primary_account_number: "4#{15.times{rand(0..9)}}",
            expiry: future.strftime('%Y%M'),
            currency_code: '987',
            transaction_amount: rand(100..9999),
            cardholder_name: 'Some Cardholder Name',
            device_manufacturer_identifier: SecureRandom.random_bytes(5).unpack('H*').first,
            online_payment_cryptogram: Base64.strict_encode64(SecureRandom.random_bytes(10)),
            eci_indicator: '5')
      end

      attr_reader :json

      def initialize(application_primary_account_number:,
                     expiry:,
                     currency_code:,
                     transaction_amount:,
                     cardholder_name:,
                     device_manufacturer_identifier:,
                     online_payment_cryptogram:,
                     eci_indicator:
                    )
        @json = {
          applicationPrimaryAccountNumber: application_primary_account_number,
          expiry:                          expiry,
          currencyCode:                    currency_code,
          transactionAmount:               transaction_amount,
          cardholderName:                  cardholder_name,
          deviceManufacturerIdentifier:    device_manufacturer_identifier,
          onlinePaymentCryptogram:         online_payment_cryptogram,
          eciIndicator:                    eci_indicator,
        }.to_json
      end

      def encrypted_with(symmetric_key:)
        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.encrypt

        cipher.key = symmetric_key
        cipher.iv_len = 16
        cipher.iv = 0.chr * cipher.iv_len

        cipher.auth_data = ''
        cipher.update(@json) + cipher.final + cipher.auth_tag
      end
    end


    def initialize(data:, ephemeral_public_key:, public_key_hash:, transaction_id:, version: 'EC_v1')
      @data                 = data
      @ephemeral_public_key = ephemeral_public_key
      @public_key_hash      = public_key_hash
      @transaction_id       = transaction_id
      @version              = version
    end

    attr_reader :data, :ephemeral_public_key, :public_key_hash, :transaction_id, :version
    attr_accessor :signature

    def to_json
      eph_key_der = ec_key_to_pkey_public_key(@ephemeral_public_key).to_der rescue @ephemeral_public_key

      {
        data: Base64.strict_encode64(@data),
        header: {
          ephemeralPublicKey: Base64.strict_encode64(eph_key_der),
          publicKeyHash: Base64.strict_encode64(@public_key_hash),
          transactionId: @transaction_id.unpack('H*').first,
        },
        signature: signature,
        version: @version,
      }.to_json
    end
  end

  class Backend
    def self.serial
      @@serial ||= 0

      @@serial += 1
    end

    def initialize(valid_for: Time.new(Time.now.year, 1, 1) .. Time.new(Time.now.year+1, 1, 1))
      new_ca(valid_for: valid_for)
      new_intermediate(valid_for: valid_for)
      new_leaf(valid_for: valid_for)
    end

    attr_accessor :ca_key, :ca_cert, :intermediate_key, :intermediate_cert, :leaf_key, :leaf_cert

    # See
    # http://ruby-doc.org/stdlib-2.3.3/libdoc/openssl/rdoc/OpenSSL/X509/Certificate.html

    def new_ca(valid_for: Time.new(Time.now.year, 1, 1) .. Time.new(Time.now.year+1, 1, 1))
      @ca_key = OpenSSL::PKey::EC.new('prime256v1')
      @ca_key.generate_key

      @ca_cert = OpenSSL::X509::Certificate.new
      @ca_cert.version = 2 # https://www.ietf.org/rfc/rfc5280.txt -> Section 4.1, search for "v3(2)".
      @ca_cert.serial = self.class.serial
      @ca_cert.subject = OpenSSL::X509::Name.parse('/C=DK/O=Pedicel Inc./OU=Pedicel Certification Authority/CN=Pedicel Root CA - G3')
      @ca_cert.issuer = @ca_cert.subject # Self-signed
      @ca_cert.public_key = ec_key_to_pkey_public_key(@ca_key)
      @ca_cert.not_before = valid_for.first
      @ca_cert.not_after = valid_for.last

      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = @ca_cert
      ef.issuer_certificate = @ca_cert
      @ca_cert.add_extension(ef.create_extension('basicConstraints','CA:TRUE',true))
      @ca_cert.add_extension(ef.create_extension('keyUsage','keyCertSign, cRLSign', true))
      @ca_cert.add_extension(ef.create_extension('subjectKeyIdentifier','hash',false))
      @ca_cert.add_extension(ef.create_extension('authorityKeyIdentifier','keyid:always',false))
      @ca_cert.sign(@ca_key, OpenSSL::Digest::SHA256.new)
    end

    def new_intermediate(valid_for: Time.new(Time.now.year, 1, 1) .. Time.new(Time.now.year+1, 1, 1),
                         ca_key: @ca_key,
                         ca_cert: @ca_cert)
      @intermediate_key = OpenSSL::PKey::EC.new('prime256v1')
      @intermediate_key.generate_key

      @intermediate_cert = OpenSSL::X509::Certificate.new
      @intermediate_cert.version = 2 # https://www.ietf.org/rfc/rfc5280.txt -> Section 4.1, search for "v3(2)".
      @intermediate_cert.serial = self.class.serial
      @intermediate_cert.subject = OpenSSL::X509::Name.parse('/C=DK/O=Pedicel Inc./OU=Pedicel Certification Authority/CN=Pedicel Application Integration CA - G3')
      @intermediate_cert.issuer = @ca_cert.subject
      @intermediate_cert.public_key = ec_key_to_pkey_public_key(@intermediate_key)
      @intermediate_cert.not_before = valid_for.first
      @intermediate_cert.not_after = valid_for.last

      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = @intermediate_cert
      ef.issuer_certificate = @ca_cert
      #@intermediate_cert.add_extension(ef.create_extension('keyUsage','digitalSignature', true))
      @intermediate_cert.add_extension(ef.create_extension('keyUsage','keyCertSign, cRLSign', true))
      @intermediate_cert.add_extension(ef.create_extension('subjectKeyIdentifier','hash',false))

      intermediate_oid_ext = OpenSSL::X509::Extension.new(Pedicel.config[:oids][:intermediate_certificate], 'asdf')
      @intermediate_cert.add_extension(intermediate_oid_ext)

      @intermediate_cert.sign(@ca_key, OpenSSL::Digest::SHA256.new)
    end

    def new_leaf(valid_for: Time.new(Time.now.year, 1, 1) .. Time.new(Time.now.year+1, 1, 1),
                 intermediate_cert: @intermediate_cert,
                 intermediate_key: @intermediate_key)
      @leaf_key = OpenSSL::PKey::EC.new('prime256v1')
      @leaf_key.generate_key

      @leaf_cert = OpenSSL::X509::Certificate.new
      @leaf_cert.version = 2 # https://www.ietf.org/rfc/rfc5280.txt -> Section 4.1, search for "v3(2)".
      @leaf_cert.serial = self.class.serial
      @leaf_cert.subject = OpenSSL::X509::Name.parse('/C=DK/O=Pedicel Inc./OU=pOS Systems/CN=ecc-smp-broker-sign_UC4-PROD')
      @leaf_cert.issuer = @intermediate_cert.subject
      @leaf_cert.public_key = ec_key_to_pkey_public_key(@leaf_key)
      @leaf_cert.not_before = valid_for.first
      @leaf_cert.not_after = valid_for.last

      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = @leaf_cert
      ef.issuer_certificate = @intermediate_cert
      @leaf_cert.add_extension(ef.create_extension('keyUsage','digitalSignature', true))
      #@leaf_cert.add_extension(ef.create_extension('keyUsage','digitalSignature, keyEncipherment, keyCertSign, cRLSign', true))
      #@leaf_cert.add_extension(ef.create_extension('keyUsage','keyCertSign, cRLSign', true))
      @leaf_cert.add_extension(ef.create_extension('subjectKeyIdentifier','hash',false))

      leaf_oid_ext = OpenSSL::X509::Extension.new(Pedicel.config[:oids][:leaf_certificate], 'foo')
      @leaf_cert.add_extension(leaf_oid_ext)

      @leaf_cert.sign(@intermediate_key, OpenSSL::Digest::SHA256.new)
    end

    def sign_csr(csr,
                 valid_for: Time.new(Time.now.year, 1, 1) .. Time.new(Time.now.year+1, 1, 1))
      cert = OpenSSL::X509::Certificate.new
      cert.serial = self.class.serial
      cert.version = 2
      cert.not_before = valid_for.first
      cert.not_after = valid_for.last
      cert.subject = OpenSSL::X509::Name.parse('/UID=merchant.dk.pedicel-merchant.PedicelMerchant/CN=Merchant ID: merchant.dk.pedicel-merchant.PedicelMerchant/OU=1W2X3Y4Z5A/O=PedicelMerchant Inc./C=DK')
      cert.public_key = csr.public_key
      cert.issuer = @intermediate_cert.issuer # My best guess.
      cert.sign(@intermediate_key, OpenSSL::Digest::SHA256.new)

      merchant_id_hex = [SecureRandom.random_bytes(32)].pack('H*')
      oid_ext = OpenSSL::X509::Extension.new(Pedicel.config[:oids][:merchant_identifier_field], merchant_id_hex)

      cert.add_extension(oid_ext)

      cert
    end

    def sign(ephemeral_public_key:, encrypted_data:, transaction_id:, application_data: nil)
      message = [
        #ec_key_to_pkey_public_key(ephemeral_public_key).to_der,
        'asdf',
        encrypted_data,
        #transaction_id,
        application_data,
      ].compact.join
      $encrypted_data = encrypted_data
      $message = message

      s = OpenSSL::PKCS7.sign(@leaf_cert, @leaf_key, message, [@intermediate_cert, @ca_cert])
      $s = s

      Base64.strict_encode64(s.to_der)
    end

    def symmetric_key(certificate:, shared_secret:)
      Pedicel::EC.symmetric_key(
        merchant_id: Pedicel::EC.merchant_id(certificate: certificate),
        shared_secret: shared_secret
      )
    end

    def shared_secret_and_ephemeral_public_key(merchant_certificate:)
      seckey = new_ephemeral_key

      pubkey = OpenSSL::PKey::EC.new(merchant_certificate.public_key).public_key

      [seckey.dh_compute_key(pubkey), seckey.public_key]
    end

    def new_ephemeral_key
      ephemeral_key = OpenSSL::PKey::EC.new('prime256v1')
      ephemeral_key.generate_key

      ephemeral_key
    end

  end
end
