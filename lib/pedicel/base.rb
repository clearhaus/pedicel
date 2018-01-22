require 'openssl'
require 'base64'

module Pedicel
  class Base
    SUPPORTED_VERSIONS = [:EC_v1]

    def initialize(token, now: Time.now)
      @token = token
    end

    def validate_content(now: Time.now)
      raise VersionError, "unsupported version: #{version}" unless SUPPORTED_VERSIONS.include?(@token['version'])

      raise ReplayAttackError, "token signature time indicates a replay attack (age #{now-cms_signing_time})" unless signing_time_ok?(now: now)

      raise SignatureError unless valid_signature?
    end

    def version
      @token['version']&.to_sym
    end

    def encrypted_data
      Base64.decode64(@token['data'])
    end

    def signature
      Base64.decode64(@token['signature'])
    end

    def transaction_id
      [@token['header']['transactionId']].pack('H*')
    end

    def application_data
      return nil unless @token['applicationData']

      [@token['applicationData']].pack('H*')
    end

    def signing_time_ok?(now: Time.now)
      # "Inspect the CMS signing time of the signature, as defined by section 11.3
      # of RFC 5652. If the time signature and the transaction time differ by more
      # than a few minutes, it's possible that the token is a replay attack."
      # https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

      delta = Pedicel.config[:replay_threshold_seconds]

      cms_signing_time.between?(now - delta, now + delta)
      # Deliberately ignoring leap seconds.
    end

    def private_key_class
      {EC_v1: OpenSSL::PKey::EC, RSA_v1: OpenSSL::PKey::RSA}[version]
    end

    def symmetric_algorithm
      {EC_v1: 'aes-256-gcm', RSA_v1: 'aes-128-gcm'}[version]
    end

    def decrypt_aes(key:)
      if OpenSSL::Cipher.new('aes-256-gcm').respond_to?(:iv_len=)
        # Either because you use Ruby >=2.4's native openssl lib, or if you have a
        # "recent enough" version of the openssl gem available.

        cipher = OpenSSL::Cipher.new(symmetric_algorithm)
        cipher.decrypt

        cipher.key = key
        cipher.iv_len = 16 # Must be set before the IV because default is 12 and
                           # only IVs of length `iv_len` will be accepted.
        cipher.iv = "\x00".b * cipher.iv_len

        split_position = encrypted_data.length - cipher.iv_len
        tag = encrypted_data.slice(split_position, cipher.iv_len)
        untagged_encrypted_data = encrypted_data.slice(0, split_position)

        cipher.auth_tag = tag
        cipher.auth_data = ''.b

        cipher.update(untagged_encrypted_data) << cipher.final
      else
        require 'aes256gcm_decrypt'

        Aes256GcmDecrypt::decrypt(encrypted_data, key)
      end
    end

    def valid_signature?(now: Time.now)
      true if validate_signature(now: now)
    rescue
      false
    end

    def verify_signature(now: Time.now)
      begin
        s = OpenSSL::PKCS7.new(signature)
      rescue => e
        raise SignatureError, "invalid PKCS #7 signature: #{e.message}"
      end

      # 1.a
      # Ensure that the certificates contain the correct custom OIDs: (...).
      # The value for these marker OIDs doesn't matter, only their presence.
      leaf, intermediate = self.class.verify_signature_certificate_oids(signature: s)

      begin
        root = OpenSSL::X509::Certificate.new(Pedicel.config[:apple_root_ca_g3_cert_pem])
      rescue => e
        raise CertificateError, "invalid root certificate: #{e.message}"
      end

      # 1.b
      # Ensure that the root CA is the Apple Root CA - G3. (...)
      self.class.verify_root_certificate(root: root, intermediate: intermediate)

      # 1.c
      # Ensure that there is a valid X.509 chain of trust from the signature to the root CA.
      self.class.verify_x509_chain(root: root, intermediate: intermediate, leaf: leaf)

      # 1.d
      # Validate the token's signature.
      #
      # Implemented in the subclass.
      validate_signature(signature: s, leaf: leaf)

      # 1.e
      # Inspect the CMS signing time of the signature (...)
      self.class.verify_signed_time(signature: s, now: now)

      self
    end

    private

    def self.verify_signature_certificate_oids(signature:)
      leaf = signature.certificates.find{|c| c.extensions.find{|e| e.oid == Pedicel.config[:oids][:leaf_certificate]}}
      unless leaf
        raise SignatureError, "no leaf certificate found (OID #{Pedicel.config[:oids][:leaf_certificate]})"
      end

      intermediate = signature.certificates.find{|c| c.extensions.find{|e| e.oid == Pedicel.config[:oids][:intermediate_certificate]}}
      unless intermediate
        raise SignatureError, "no intermediate certificate found (OID #{Pedicel.config[:oids][:leaf_certificate]})"
      end

      [leaf, intermediate]
    end

    def self.verify_root_certificate(root:, intermediate:)
      unless intermediate.issuer == root.subject
        raise SignatureError, 'root certificate has not issued intermediate certificate'
      end
    end

    def self.verify_x509_chain(root:, intermediate:, leaf:)
      valid_chain = OpenSSL::X509::Store.new.
                      add_cert(root).
                      add_cert(intermediate).
                      verify(leaf)

      raise SignatureError, 'invalid chain of trust' unless valid_chain
    end

    def self.verify_signed_time(signature:, now:)
      # Inspect the CMS signing time of the signature, as defined by section
      # 11.3 of RFC 5652. If the time signature and the transaction time differ
      # by more than a few minutes, it's possible that the token is a replay
      # attack.

      unless signature.signers.length == 1
        raise SignatureError, 'not 1 signer, unable to determine signing time'
      end
      signed_time = signature.signers.first.signed_time

      few_min = Pedicel.config[:replay_threshold_seconds]

      # Time objects. DST aware. Ignoring leap seconds.
      return if signed_time.between?(now - few_min, now + few_min) # Both ends included.

      diff = signed_time - now
      if diff.negative?
        raise SignatureError, "signature too old; signed #{-diff.to_i}s ago"
      end
      raise SignatureError, "signature too new; signed #{diff.to_i}s in the future"
    end
  end
end
