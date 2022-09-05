require 'pedicel/base'

module Pedicel
  class EC < Base
    def ephemeral_public_key
      @token[:header].transform_keys!(&:to_sym)

      Base64.decode64(@token[:header][:ephemeralPublicKey])
    end

    def decrypt(symmetric_key: nil, merchant_id: nil, certificate: nil, private_key: nil,
                ca_certificate_pem: @config[:trusted_ca_pem], now: Time.now)
      # Check for necessary parameters.
      unless symmetric_key || ((merchant_id || certificate) && private_key)
        raise ArgumentError, 'missing parameters'
      end

      # Check for uniqueness among the supplied parameters used directly here.
      if symmetric_key && (merchant_id || certificate || private_key)
        raise ArgumentError, "leave out other parameters when supplying 'symmetric_key'"
      end

      verify_signature(ca_certificate_pem: ca_certificate_pem, now: now)

      symmetric_key ||= symmetric_key(private_key: private_key,
                                      merchant_id: merchant_id,
                                      certificate: certificate)

      decrypt_aes(key: symmetric_key)
    end

    def symmetric_key(private_key: nil, merchant_id: nil, certificate: nil)
      # Check for necessary parameters.
      unless private_key && (merchant_id || certificate)
        raise ArgumentError, 'missing parameters'
      end

      # Check for uniqueness among the supplied parameters.
      if merchant_id && certificate
        raise ArgumentError, "leave out 'certificate' when supplying 'merchant_id'"
      end

      shared_secret = shared_secret(private_key: private_key)

      merchant_id ||= self.class.merchant_id(certificate: certificate, mid_oid: @config[:oid_merchant_identifier_field])

      self.class.symmetric_key(shared_secret: shared_secret, merchant_id: merchant_id)
    end

    def shared_secret(private_key:)
      begin
        privkey = OpenSSL::PKey::EC.new(private_key)
      rescue => e
        raise EcKeyError, "invalid PEM format of private key for EC: #{e.message}"
      end

      begin
        pubkey = OpenSSL::PKey::EC.new(ephemeral_public_key).public_key
      rescue => e
        raise EcKeyError, "invalid ephemeralPublicKey (from token) for EC: #{e.message}"
      end

      unless privkey.group == pubkey.group
        raise EcKeyError, "private_key curve '%s' differs from token ephemeralPublicKey curve '%s'" %
                          [privkey.group.curve_name, pubkey.group.curve_name]
      end

      privkey.dh_compute_key(pubkey)
    end

    def self.symmetric_key(merchant_id:, shared_secret:)
      raise ArgumentError, 'merchant_id must be a SHA256' unless merchant_id.is_a?(String) && merchant_id.length == 32
      raise ArgumentError, 'shared_secret must be a string' unless shared_secret.is_a?(String)

      # http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
      # Section 5.8.1.1, The Single-Step KDF Specification.
      #
      # With slight adjustments:
      # > 1. Set `reps = ceil(keydatalen/hashlen)`
      # > 2. If `reps > (2^32 - 1)`, then return an error indicator without
      # >    performing the remaining actions.
      # > 3. Initialize a 32-bit, big-endian bit string `counter` as 00000001 base
      # >    16 (i.e. 0x00000001).
      # > 4. If `counter || Z || OtherInfo` is more than `max_H_inputlen` bits
      # >    long, then return an error indicator without performing the remaining
      # >    actions.
      # > 5. For `i = 1` to `reps` by `1`, do the following:
      # >      5.1  Compute `K(i) = H(counter || Z || OtherInfo)`.
      # >      5.2  Increment `counter` (modulo `2^32`), treating it as an
      # >           unsigned 32-bit integer.
      # > 6. Let `K_Last` be set to `K(reps)` if `keydatalen / hashlen` is an
      # >    integer; otherwise, let `K_Last` be set to the `keydatalen mod
      # >    hashlen` leftmost bits of `K(reps)`.
      # > 7. Return `K(1) || K(2) || ... || K(reps-1) || K_Last`.
      #
      # Digest::SHA256 will do the calculations when we throw Z and OtherInfo
      # into the digest.

      sha256 = Digest::SHA256.new

      # Step 3
      sha256 << "\x00\x00\x00\x01"

      # Z
      sha256 << shared_secret

      # OtherInfo
      # https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html
      sha256 << "\x0d" + 'id-aes256-GCM' # AlgorithmID
      sha256 << 'Apple' # PartyUInfo
      sha256 << merchant_id # PartyVInfo

      sha256.digest
    end

    def self.merchant_id(certificate:, mid_oid: Pedicel::DEFAULT_CONFIG[:oid_merchant_identifier_field])
      begin
        cert = OpenSSL::X509::Certificate.new(certificate)
      rescue => e
        raise CertificateError, "invalid PEM format of certificate: #{e.message}"
      end

      merchant_id_hex =
        cert
        .extensions
        .find { |x| x.oid == mid_oid }
        &.value # Hex encoded Merchant ID plus perhaps extra non-hex chars.
        &.delete('^[0-9a-fA-F]') # Remove non-hex chars.

      raise CertificateError, 'no merchant identifier in certificate' unless merchant_id_hex

      [merchant_id_hex].pack('H*')
    end

    private

    def validate_signature(signature:, leaf:)
      # (...) ensure that the signature is a valid ECDSA signature
      # (ecdsa-with-SHA256 1.2.840.10045.4.3.2) of the concatenated values of
      # the ephemeralPublicKey, data, transactionId, and applicationData keys.

      unless leaf.signature_algorithm == 'ecdsa-with-SHA256'
        raise SignatureError, 'signature algorithm is not ecdsa-with-SHA256'
      end

      message = [
        ephemeral_public_key,
        encrypted_data,
        transaction_id,
        application_data,
      ].compact.join

      # https://wiki.openssl.org/index.php/Manual:PKCS7_verify(3)#VERIFY_PROCESS
      flags = \
        OpenSSL::PKCS7::NOCHAIN  | # Ignore certs in the message.
        OpenSSL::PKCS7::NOINTERN | # Only look at the supplied certificate.
        OpenSSL::PKCS7::NOVERIFY   # Do not verify the chain; already done.

      # Trust exactly the leaf which has already been verified.
      certificates = [leaf]

      store = OpenSSL::X509::Store.new

      unless signature.verify(certificates, store, message, flags)
        raise SignatureError, 'signature does not match the message'
      end

      true
    end
  end
end
