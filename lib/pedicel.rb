require 'factory'
require 'base'
require 'ec'
require 'rsa'

module Pedicel
  class Error < StandardError; end
  class TokenFormatError < Error; end
  class SignatureError < Error; end
  class VersionError < Error; end
  class CertificateError < Error; end
  class EcKeyError < Error; end
  class EcEphemeralPublicKeyError < Error; end

  DEFAULTS = {
    oids: {
      intermediate_certificate:  '1.2.840.113635.100.6.2.14',
      leaf_certificate:          '1.2.840.113635.100.6.29',
      merchant_identifier_field: '1.2.840.113635.100.6.32',
    },
    replay_threshold_seconds: 3*60,
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

  def self.config
    @@config ||= DEFAULTS
  end

  def self.config=(other)
    @@config = other
  end
end
