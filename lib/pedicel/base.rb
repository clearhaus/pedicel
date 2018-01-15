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
  end
end
