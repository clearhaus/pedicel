require 'base'

module Pedicel
  class EC < Base
    def ephemeral_public_key
      Base64.decode64(@token['header']['ephemeralPublicKey'])
    end

    def decrypt(symmetric_key: nil, merchant_id: nil, certificate: nil, private_key: nil, now: Time.now)
      raise ArgumentError 'invalid argument combination' unless \
        !symmetric_key.nil? ^ ((!merchant_id.nil? ^ !certificate.nil?) && !private_key.nil?)
      # .-------------------'--------. .----------'----. .-------------''---.
      # | symmetric_key can be       | | merchant_id   | | Both private_key |
      # | derived from private_key   | | (byte string) | | and merchant_id  |
      # | and the shared_secret---   | | can be        | | is necessary to  |
      # | which can be derived from  | | derived from  | | derive the       |
      # | the private_key and the    | | the public    | | symmetric key    |
      # | token's ephemeralPublicKey | | certificate   | '------------------'
      # '----------------------------' '---------------'

      if private_key
        symmetric_key = symmetric_key(private_key: private_key,
                                      certificate: certificate,
                                      merchant_id: merchant_id)
      end

      verify_signature(now: now)
      decrypt_aes(key: symmetric_key)
    end

    def symmetric_key(shared_secret: nil, private_key: nil, merchant_id: nil, certificate: nil)
      raise ArgumentError 'invalid argument combination' unless \
        (!shared_secret.nil? ^ !private_key.nil?) && (!merchant_id.nil? ^ !certificate.nil?)
      # .--------------------'.  .----------------'|  .-----------------'--.
      # | shared_secret can   |  | shared_secret   |  | merchant_id (byte  |
      # | be derived from the |  | and merchant_id |  | string can be      |
      # | private_key and the |  | is necessary to |  | derived from the   |
      # | ephemeralPublicKey  |  | derive the      |  | public certificate |
      # '---------------------'  | symmetric_key   |  '--------------------'
      #                          '-----------------'

      shared_secret = shared_secret(private_key: private_key) if private_key
      merchant_id = self.class.merchant_id(certificate: certificate) if certificate

      self.class.symmetric_key(shared_secret: shared_secret, merchant_id: merchant_id)
    end

    # Extract the shared secret from one public key (the ephemeral) and one
    # private key.
    def shared_secret(private_key:)
      begin
        privkey = OpenSSL::PKey::EC.new(private_key)
      rescue => e
        raise EcKeyError, "invalid PEM format of private key for EC: #{e.message}"
      end

      begin
        pubkey = OpenSSL::PKey::EC.new(ephemeral_public_key).public_key
      rescue => e
        raise EcKeyError, "invalid format of ephemeralPublicKey (from token) for EC: #{e.message}"
      end

      unless privkey.group == pubkey.group
        raise EcKeyError,
          "private_key curve '#{privkey.group.curve_name}' differ from " \
          "ephemeralPublicKey (from token) curve '#{pubkey.group.curve_name}'"
      end

      privkey.dh_compute_key(pubkey)
    end

    def self.symmetric_key(merchant_id:, shared_secret:)
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
      # Digest::SHA256 will do the calculations when we throw Z and OtherInfo into
      # the digest.

      sha256 = Digest::SHA256.new

      # Step 3:
      sha256 << "\x00\x00\x00\x01"

      # Z:
      sha256 << shared_secret

      # OtherInfo:
      # https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html
      sha256 << "\x0d" + 'id-aes256-GCM' # AlgorithmID
      sha256 << 'Apple' # PartyUInfo
      sha256 << merchant_id # PartyVInfo

      sha256.digest
    end

    def self.merchant_id(certificate:)
      begin
        cert = OpenSSL::X509::Certificate.new(certificate)
      rescue => e
        raise CertificateError, "Invalid PEM format of certificate: #{e.message}"
      end

      bytestrings = [
        cert.
          extensions.
          find { |x| x.oid == Pedicel.config[:oids][:merchant_identifier_field] }&.
          value&. # Hex encoded Merchant ID plus perhaps extra non-hex chars.
          delete("^[0-9a-fA-F]") # Remove non-hex chars.
      ].compact

      raise CertificateError, 'no merchant identifier in certificate' if bytestrings.empty?

      bytestrings.pack('H*')
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
    end
  end
end
