require 'openssl'

module Pedicel
  class Base
    SUPPORTED_VERSIONS = [:EC_v1]

    def initialize(token, now: Time.now)
      @token = Pedicel.config[:json_parser].call(token)

      validate(now: now)
    end

    def validate(now: Time.now)
      validate_format
      validate_content(now: now)
    end

    def validate_format
      keys = ['data', 'header', 'signature', 'version']
      missing = @token.values_at(keys).select{|k,v| v.nil?}.keys

      # FIXME: ephemeralPublicKey is for EC, wrappedKey is for RSA; etc.
      header_keys = ['applicationData', 'ephemeralPublicKey', 'wrappedKey', 'publicKeyHash', 'transactionId']
      missing.concat(@token['header'].values_at(header_keys).select{|k,v| v.nil?}.keys.map{|k| "header.#{k}"})

      raise TokenFormatError, 'Token missing keys: ' + missing.join(', ') unless missing.empty?
    end

    def validate_content(now: Time.now)
      raise VersionError, "unsupported version: #{version}" unless SUPPORTED_VERSIONS.include?(@token['version'])

      raise ReplayAttackError, "token signature time indicates a replay attack (age #{now-cms_signing_time})" unless signing_time_ok?(now: now)

      raise SignatureError unless valid_signature?
    end

    def version
      @token['version']&.to_sym
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

    def merchant_id(certificate)
      [certificate.
         extensions.
         find { |e| e.oid == Pedicel.config[:oids][:merchant_identifier_field] }.
         value # Hex encoded Merchant ID.
      ].pack('H*')
    end
  end
end
