require 'openssl'

class Pedicel
  class Error < StandardError; end
  class TokenFormatError < Error; end
  class SignatureError < Error; end
  class VersionError < Error; end
  class KeyError < Error; end

  DEFAULTS = {
    oids: {
      intermediate_certificate:  '1.2.840.113635.100.6.2.14',
      leaf_certificate:          '1.2.840.113635.100.6.29',
      merchant_identifier_field: '1.2.840.113635.100.6.32',
    },
    replay_age_threshold: 3*60, # seconds
    json_parser: lambda{|string| require 'json'; JSON.parse(string)},
    apple_root_ca_g3_cert_pem: <<~PEM
    -----BEGIN CERTIFICATE-----
    MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS
    QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
    IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN
    MTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBS
    b290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9y
    aXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49
    AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtf
    TjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517
    IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySr
    MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gA
    MGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4
    at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM
    6BgD56KyKA==
    -----END CERTIFICATE-----
    PEM
  }

  class << self
    def config
      @config ||= DEFAULTS
    end
    def config=(other)
      @config = other
    end
  end

  def initialize(token)
    @token = Pedicel.config[:json_parser].call(token)

    validate
  end

  SUPPORTED_VERSIONS = %i{:EC_v1, :RSA_v1}

  def version
    {'EC_v1' => :EC_v1, 'RSA_v1' => :RSA_v1}[@token['version']]
  end

  def header
    @token['header']
  end

  def ephemeral_public_key
    @token['ephemeralPublicKey']
  end

  def validate
    validate_token
  end

  def validate_token
    validate_token_format
    validate_token_content
  end

  def validate_token_format
    keys = ['data', 'header', 'signature', 'version']
    missing = @token.values_at(keys).select{|k,v| v.nil?}.keys

    header_keys = ['applicationData', 'ephemeralPublicKey', 'wrappedKey', 'publicKeyHash', 'transactionId']
    missing.concat(@token['header'].values_at(header_keys).select{|k,v| v.nil?}.keys.map{|k| "header.#{k}"})

    raise TokenFormatError, 'Token missing keys: ' + missing.join(', ') unless missing.empty?
  end

  def validate_token_content
    raise VersionError unless SUPPORTED_VERSIONS.include?(@token['version'])
  end

  def decrypt(private_key: nil, symmetric_key: nil)
    raise SignatureError unless valid_signature?

    case
    when symmetric_key then decrypt_aes(symmetric_key(private_key))
    when private_key   then decrypt_aes(digest)
    else raise ArgumentError, 'Missing key'
    end
  end

  def merchant_id
  end

  def cms_signing_time
    fail 'Not implemented yet'
  end

  def signing_time_ok?(threshold: nil)
    recent_enough?(threshold: threshold) && !signed_in_the_future?
  end

  def signed_in_the_future?
    Time.now < cms_signing_time
  end

  def recent_enough?(threshold: nil)
    # "Inspect the CMS signing time of the signature, as defined by section 11.3
    # of RFC 5652. If the time signature and the transaction time differ by more
    # than a few minutes, it's possible that the token is a replay attack."
    # https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

    threshold ||= Pedicel.config[:replay_age_threshold]

    Time.now - threshold <= cms_signing_time # Deliberately ignoring leap seconds.
  end

  def symmetric_key(private_key)
    begin
      private_key = private_key_class.new(pem)
    rescue => e
      raise KeyError, "Invalid PEM format of private key for #{version}: #{e.message}"
    end

    send(symmetric_key_method, private_key)
  end

  def private_key_class
    {EC_v1: OpenSSL::PKey::EC, RSA_v1: OpenSSL::PKey::RSA}[version]
  end

  def symmetric_key_method
    {EC_v1: :symmetric_key_ec, RSA_v1: :symmetric_key_rsa}[version]
  end

  def symmetric_algorithm
    {EC_v1: 'aes-256-gcm', RSA_v1: 'aes-128-gcm'}[version]
  end

  private

  def symmetric_key_ec(private_key)
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
    sha256 << "\x00\x00\x00\x01".b
    # FIXME: Can't we do without `#b` that encodes it ASCII-8BIT? Throughout the
    # entire file!

    # Z:
    sha256 << shared_secret(private_key)

    # OtherInfo:
    # https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html
    sha256 << "\x0d".b + 'id-aes256-GCM' # AlgorithmID
    sha256 << 'Apple' # PartyUInfo
    sha256 << party_v # PartyVInfo

    sha256.digest
  end

  def symmetric_key_rsa(private_key)
    # RSA/ECB/OAEPWithSHA256AndMGF1Padding

    # OpenSSL::PKey::RSA#private_decrypt will use SHA1. Only. :-(

    raise Error, 'RSA_v1 not implemented yet'
  end

  def shared_secret(private_key)
    private_key_class.new(Base64.decode64(ephemeral_public_key))
  end

  def party_v
    [OpenSSL::X509::Certificate.new(certificate)
      .extensions
      .find { |e| e.oid == Pedicel.config[:oids][:merchant_identifier_field] }
      .value # Hex encoded Merchant ID.
    ].pack('H*')
  end


  def decrypt_aes(key)
    # WARNING! The below is a guess! Review needed!
    # The splitting is quite likely not necessary.

    split_position = encrypted_data.length - cipher.iv_len
    tag = encrypted_data.slice(split_position, cipher.iv_len)
    untagged_encrypted_data = encrypted_data.slice(0, split_position)

    if OpenSSL::Cipher.new('aes-256-gcm').respond_to?(:iv_len=)
      # Either because you use Ruby >=2.4's native openssl lib, or if you have a
      # "recent enough" version of the openssl gem available.

      cipher = OpenSSL::Cipher.new(symmetric_algorithm)
      cipher.decrypt

      cipher.key = key
      cipher.iv_len = 16 # Must be set before the IV because default is 12 and
      # only IVs of length `iv_len` will be accepted.
      cipher.iv = "\x00".b * cipher.iv_len

      cipher.auth_tag = tag
      cipher.auth_data = ''.b

      cipher.update(untagged_encrypted_data) << cipher.final
    else
      require 'aes256gcm_decrypt'

      Aes256GcmDecrypt::decrypt(untagged_encrypted_data, tag, key)
    end
  end
end
