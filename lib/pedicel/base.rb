require 'openssl'
require 'base64'
require 'pedicel/validator'

module Pedicel
  class Base
    SUPPORTED_VERSIONS = [:EC_v1].freeze

    attr_reader :config

    def initialize(token, config: Pedicel::DEFAULT_CONFIG)
      validation = Validator::Token.new(token)
      validation.validate

      @token  = validation.output
      @config = config
    end

    def version
      @token[:version].to_sym
    end

    def encrypted_data
      return nil unless @token[:data]

      Base64.decode64(@token[:data])
    end

    def signature
      return nil unless @token[:signature]

      Base64.decode64(@token[:signature])
    end

    def transaction_id
      [@token[:header][:transactionId]].pack('H*')
    end

    def application_data
      return nil unless @token[:header][:applicationData]

      [@token[:header][:applicationData]].pack('H*')
    end

    def private_key_class
      raise VersionError, "unsupported version: #{version}" unless SUPPORTED_VERSIONS.include?(version)

      { EC_v1: OpenSSL::PKey::EC, RSA_v1: OpenSSL::PKey::RSA }[version]
    end

    def symmetric_algorithm
      raise VersionError, "unsupported version: #{version}" unless SUPPORTED_VERSIONS.include?(version)

      { EC_v1: 'aes-256-gcm', RSA_v1: 'aes-128-gcm' }[version]
    end

    def decrypt_aes(key:)
      raise TokenFormatError, 'no encrypted data present' unless encrypted_data

      if OpenSSL::Cipher.new('aes-256-gcm').respond_to?(:iv_len=)
        # Either because you use Ruby >=2.4's native openssl lib, or if you have
        # a "recent enough" version of the openssl gem available.
        decrypt_aes_openssl(key)
      else
        decrypt_aes_gem(key)
      end
    end

    private def decrypt_aes_openssl(key)
      cipher = OpenSSL::Cipher.new(symmetric_algorithm)
      cipher.decrypt

      begin
        cipher.key = key
      rescue ArgumentError => e
        raise Pedicel::AesKeyError, "invalid key: #{e.message}"
      end

      # iv_len must be set before the IV because default is 12 and
      # only IVs of length `iv_len` will be accepted.
      cipher.iv_len = 16
      cipher.iv = 0.chr * cipher.iv_len

      split_position = encrypted_data.length - cipher.iv_len
      tag = encrypted_data.slice(split_position, cipher.iv_len)
      untagged_encrypted_data = encrypted_data.slice(0, split_position)

      cipher.auth_tag = tag
      cipher.auth_data = ''.b

      cipher.update(untagged_encrypted_data) << cipher.final
    rescue OpenSSL::Cipher::CipherError
      raise Pedicel::AesKeyError, 'wrong key'
    end

    private def decrypt_aes_gem(key)
      require 'aes256gcm_decrypt'

      Aes256GcmDecrypt.decrypt(encrypted_data, key)
    rescue Aes256GcmDecrypt::Error => e
      raise Pedicel::AesKeyError, "decryption failed: #{e}"
    end

    def valid_signature?(now: Time.now)
      !!verify_signature(now: now)
    rescue
      false
    end

    def verify_signature(ca_certificate_pem: @config[:trusted_ca_pem], now: Time.now)
      raise SignatureError, 'no signature present' unless signature

      begin
        s = OpenSSL::PKCS7.new(signature)
      rescue => e
        raise SignatureError, "invalid PKCS #7 signature: #{e.message}"
      end

      begin
        trusted_root = OpenSSL::X509::Certificate.new(ca_certificate_pem)
      rescue => e
        raise CertificateError, "invalid trusted root certificate: #{e.message}"
      end

      # 1.a
      # Ensure that the certificates contain the correct custom OIDs: (...).
      # The value for these marker OIDs doesn't matter, only their presence.
      leaf, intermediate, other = self.class.extract_certificates(signature: s,
                                                                  intermediate_oid: @config[:oid_intermediate_certificate],
                                                                  leaf_oid: @config[:oid_leaf_certificate])
      # Implicit since these are the ones extracted.

      # 1.b
      # Ensure that the root CA is the Apple Root CA - G3. (...)
      if other
        self.class.verify_root_certificate(trusted_root: trusted_root, root: other)
        # Allow no other certificate than the root.
      #else
        # no other certificate is not extracted from the signature, and thus, we
        # trust the trusted root.
      end

      # 1.c
      # Ensure that there is a valid X.509 chain of trust from the signature to
      # the root CA.
      self.class.verify_x509_chain(root: trusted_root, intermediate: intermediate, leaf: leaf)
      # We "only" check the *certificate* chain (from leaf to root). Below (in
      # 1.d) is checked that the signature is created with the leaf.

      # 1.d
      # Validate the token's signature.
      #
      # Implemented in the subclass.
      validate_signature(signature: s, leaf: leaf)

      # 1.e
      # Inspect the CMS signing time of the signature (...)
      self.class.verify_signed_time(signature: s, now: now, few_min: @config[:replay_threshold_seconds])

      self
    end

    def self.extract_certificates(signature:,
                                  intermediate_oid: Pedicel::DEFAULT_CONFIG[:oid_intermediate_certificate],
                                  leaf_oid:         Pedicel::DEFAULT_CONFIG[:oid_leaf_certificate])
      leafs, intermediates, others = [], [], []

      signature.certificates.each do |certificate|
        leaf_or_intermediate = false

        certificate.extensions.each do |extension|
          case extension.oid
          when intermediate_oid
            intermediates << certificate
            leaf_or_intermediate = true
          when leaf_oid
            leafs << certificate
            leaf_or_intermediate = true
          end
        end

        others << certificate unless leaf_or_intermediate
      end

      raise SignatureError, "no unique leaf certificate found (OID #{leaf_oid})" unless leafs.length == 1
      raise SignatureError, "no unique intermediate certificate found (OID #{intermediate_oid})" unless intermediates.length == 1
      raise SignatureError, "too many certificates found in the signature: #{others.map(&:subject).join('; ')}" if others.length > 1

      [leafs.first, intermediates.first, others.first]
    end

    def self.verify_root_certificate(root:, trusted_root:)
      raise SignatureError, 'root certificate is not trusted' unless root.to_der == trusted_root.to_der

      true
    end

    def self.verify_x509_chain(root:, intermediate:, leaf:)
      store = OpenSSL::X509::Store.new.add_cert(root)

      unless store.verify(root)
        raise SignatureError, "invalid chain due to root: #{store.error_string}"
      end

      unless store.verify(intermediate)
        raise SignatureError, "invalid chain due to intermediate: #{store.error_string}"
      end

      begin
        store.add_cert(intermediate)
      rescue OpenSSL::X509::StoreError
        raise SignatureError, "invalid chain due to intermediate"
      end

      begin
        store.add_cert(leaf)
      rescue OpenSSL::X509::StoreError
        raise SignatureError, "invalid chain due to leaf"
      end

      unless store.verify(leaf)
        raise SignatureError, "invalid chain due to leaf: #{store.error_string}"
      end

      true
    end

    def self.verify_signed_time(signature:, now: Time.now, few_min: Pedicel::DEFAULT_CONFIG[:replay_threshold_seconds])
      # Inspect the CMS signing time of the signature, as defined by section
      # 11.3 of RFC 5652. If the time signature and the transaction time differ
      # by more than a few minutes, it's possible that the token is a replay
      # attack.
      # https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

      unless signature.signers.length == 1
        raise SignatureError, 'not 1 signer, unable to determine signing time'
      end
      signed_time = signature.signers.first.signed_time

      # Time objects. DST aware. Ignoring leap seconds. Both ends included.
      return true if signed_time.between?(now - few_min, now + few_min)

      diff = signed_time - now
      if diff.negative?
        raise SignatureError, "signature too old; signed #{-diff}s ago"
      end
      raise SignatureError, "signature too new; signed #{diff}s in the future"
    end
  end
end
