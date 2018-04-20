# frozen_string_literal: true

require 'openssl'
require 'base64'

module Pedicel
  #
  class Base # rubocop:disable Metrics/ClassLength
    SUPPORTED_VERSIONS = %i[EC_v1].freeze

    def initialize(token, config: Pedicel.config)
      @token  = token
      @config = config
    end

    def validate_content
      raise VersionError, "unsupported version: #{version}" unless SUPPORTED_VERSIONS.include?(version)

      raise SignatureError unless valid_signature?

      true
    end

    def version
      @token['version']&.to_sym
    end

    def encrypted_data
      return nil unless @token['data']

      Base64.decode64(@token['data'])
    end

    def signature
      return nil unless @token['signature']

      Base64.decode64(@token['signature'])
    end

    def transaction_id
      [@token['header']['transactionId']].pack('H*')
    end

    def application_data
      return nil unless @token['applicationData']

      [@token['applicationData']].pack('H*')
    end

    def private_key_class
      { EC_v1: OpenSSL::PKey::EC, RSA_v1: OpenSSL::PKey::RSA }[version]
    end

    def symmetric_algorithm
      { EC_v1: 'aes-256-gcm', RSA_v1: 'aes-128-gcm' }[version]
    end

    def decrypt_aes(key:)
      raise TokenFormatError, 'no encrypted data present' unless encrypted_data

      if OpenSSL::Cipher.new('aes-256-gcm').respond_to?(:iv_len=)
        # Either because you use Ruby >=2.4's native openssl lib, or if you have
        # a "recent enough" version of the openssl gem available.

        cipher = OpenSSL::Cipher.new(symmetric_algorithm)
        cipher.decrypt

        cipher.key = key

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
      else
        require 'aes256gcm_decrypt'

        Aes256GcmDecrypt.decrypt(encrypted_data, key)
      end
    end

    def valid_signature?(now: Time.now)
      true if verify_signature(now: now)
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

      # 1.a
      # Ensure that the certificates contain the correct custom OIDs: (...).
      # The value for these marker OIDs doesn't matter, only their presence.
      leaf, intermediate =
        self.class.verify_signature_certificate_oids(signature: s)

      begin
        root = OpenSSL::X509::Certificate.new(ca_certificate_pem)
      rescue => e
        raise CertificateError, "invalid root certificate: #{e.message}"
      end

      # 1.b
      # Ensure that the root CA is the Apple Root CA - G3. (...)
      self.class.verify_root_certificate(root: root, intermediate: intermediate)

      # 1.c
      # Ensure that there is a valid X.509 chain of trust from the signature to
      # the root CA.
      self.class.verify_x509_chain(root: root,
                                   intermediate: intermediate,
                                   leaf: leaf)

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

    def self.verify_signature_certificate_oids(signature:, config: Pedicel.config)
      leaf = signature.certificates.find do |c|
        c.extensions.find do |e|
          e.oid == config[:oids][:leaf_certificate]
        end
      end

      unless leaf
        raise SignatureError, "no leaf certificate found (OID #{config[:oids][:leaf_certificate]})"
      end

      intermediate = signature.certificates.find do |c|
        c.extensions.find do |e|
          e.oid == config[:oids][:intermediate_certificate]
        end
      end

      unless intermediate
        raise SignatureError, "no intermediate certificate found (OID #{config[:oids][:leaf_certificate]})"
      end

      [leaf, intermediate]
    end

    def self.verify_root_certificate(root:, intermediate:)
      unless intermediate.issuer == root.subject
        raise SignatureError,
              'root certificate has not issued intermediate certificate'
      end
    end

    def self.verify_x509_chain(root:, intermediate:, leaf:)
      valid_chain = OpenSSL::X509::Store.new
                                        .add_cert(root)
                                        .add_cert(intermediate)
                                        .verify(leaf)

      raise SignatureError, 'invalid chain of trust' unless valid_chain
    end

    def self.verify_signed_time(signature:, now:, config: Pedicel.config)
      # Inspect the CMS signing time of the signature, as defined by section
      # 11.3 of RFC 5652. If the time signature and the transaction time differ
      # by more than a few minutes, it's possible that the token is a replay
      # attack.
      # https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

      unless signature.signers.length == 1
        raise SignatureError, 'not 1 signer, unable to determine signing time'
      end
      signed_time = signature.signers.first.signed_time

      few_min = config[:replay_threshold_seconds]

      # Time objects. DST aware. Ignoring leap seconds.
      # Both ends included.
      return if signed_time.between?(now - few_min, now + few_min)

      diff = signed_time - now
      if diff.negative?
        raise SignatureError, "signature too old; signed #{-diff.to_i}s ago"
      end
      raise SignatureError, "signature too new; signed #{diff.to_i}s in the future"
    end
  end
end
