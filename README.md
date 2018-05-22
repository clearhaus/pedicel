# Pedicel

The stilk of an apple is also called a pedicel.

This Ruby gem will help you handle an Apple Pay `PKPaymentToken`.

## Usage

```ruby
# Parse the payment token into a hash
apple_pay_payment_token_hash = JSON.parse(apple_pay_payment_token_json)

# Instantiate.
# Validates the format of the Apple Pay payment token; raises an
# Pedicel::Validator::Error if the format is invalid.
pedicel = Pedicel::EC.new(apple_pay_payment_token_hash)

# Decrypt using the symmetric key directly.
# The symmetric key `sk` is derived from the private key and either the
# merchant id directly the merchant certificate.
data = pedicel.decrypt(symmetric_key: sk)

# Decrypt using the merchant private key and merchant certificate.
# The merchant private key `pk` and merchant certificate `c` is generated
# during the Apple Pay merchant sign-up.
data = pedicel.decrypt(private_key: pk, certificate: c)

# Decrypt using the merchant private key and merchant id.
# The merchant private key `pk` and merchant id `mid` is generated during the
# Apple Pay merchant sign-up.
data = pedicel.decrypt(private_key: pk, merchant_id: mid)

# Validate the decrypted data; raises an Pedicel::Validator::Error if the
# format is invalid.
Pedicel::Validator.validate_token_data(data)

# Extract the symmetric key for another party to decrypt (without compromising
# your private key).
sk = pedicel.symmetric_key(private_key: pk, certificate: c)
# or
sk = pedicel.symmetric_key(private_key: pk, merchant_id: mid)
```

## Complete test using `pedicel-pay`

```ruby
require 'pedicel-pay'
require 'pedicel'
require 'pp'

backend = PedicelPay::Backend.generate
client = backend.generate_client

token = PedicelPay::Token.new.sample
backend.encrypt_and_sign(token, recipient: client)

puts 'Your token:'
pp token

apple_pay_payment_token_json = token.to_hash.to_json

puts 'Your Apple Pay payment token:'
puts apple_pay_payment_token_json

puts 'Trust your newly generate root CA certificate:'
c = Pedicel::DEFAULT_CONFIG.merge(trusted_ca_pem: backend.ca_certificate.to_pem)
pp c

pedicel = Pedicel::EC.new(JSON.parse(apple_pay_payment_token_json), config: c)

puts 'Your decrypted data:'
data = pedicel.decrypt(private_key: client.key, certificate: client.certificate)
pp JSON.parse(data)
```

Sample output

```
Your token:
#<PedicelPay::Token:0x000000000213cbd8
 @encrypted_data=
  "\xC1xJ\xA3\xD2\x93*\xCE\xBE\xA7;\xEA\xEB\x15\f\xD8H@\x9CE\xB4\xF1\xFAke[$`^\xC5:>\xFE\xFCS~\xF2\x12\xA3\xE1\x95\x92\x8C\xD9\xE3\xB61\x04\x02!\xA8\x9C\xBF\xD3\xF4\xCE\xC7\xD9\xFE\xD5:\x8C\x84p\x92QQ\x1AgA\x9B\xA8&\xD3c^\xC4S\xD2\xCB\xA3\x107'\x8A\"\xE9\xC9\xA8\xDDq$\xE0\x85p#p\x06\xEE\xA2\x98o\x94\xEB\xA9>\xBA\x9C\x0E\xCF$\x1F\x97\xE8\xA0\xC2\xEE\xE0h\xEE\x9F\x87\x9A\x85\x98\xB6\xDA\b\xA56E\eE\xB5\xE3\xE6\xF0\x01<\x80\xF1\xF9\x16\x86\x8E\xE0P\x0E\x03\x8D\xF9\xA3 /f.\xAD\xB9jmJ\xAAA\xAE\xD3\xA7\xAF\"\x1F\xE3\xE5^\x15|\xAE\xA0\xFB\xC1D,\x9E\x1C\xCDc%B\xEC'\xB2\x9E\x84\x80o\x9B#\"\x844\xDC\xCA\x1A\xA7c\xB7\x00\xB1l=+\xBC&\x1D\x9E\x9E\x99\xCB\xDB\xB4\xACg\x1A\x13%2\xA3\x1C-\x98I\x18\xCF\xC3\xBD-\xB5=\xBB\xF2\xCA\x13_ \x83Ti\x1EN^\x99\xC2XE4A% \xA2\xC0G\xCDZ\xD1\x89'\xCB\x83\xD5\xD2\x94\xA8\xA3]\xDAr\xB8g\xE3\xFC\xE1\x94.T\xEDjKz\xBA\xE3\xE6z\xB9\xEA\xA4\xD0@\xBA\xE0&\x0Fx5! F\xBB\x9D0l",
 @header=
  #<PedicelPay::TokenHeader:0x0000000002127b98
   @data_hash=nil,
   @ephemeral_pubkey=
    #<OpenSSL::PKey::EC::Point:0x00000000021279e0
     @group=#<OpenSSL::PKey::EC::Group:0x00000000021279b8>>,
   @pubkey_hash="NbAOcxYJGFDg1I7JNdMFIYMMYV+E02ueUlYTPbArxb4=",
   @transaction_id=
    "\xB8\xF3\x80\xF1\xB3\xCB{\xDE\x9C\xF7\xB8\x81\x99Nu=\xA8\xA6`\xBB\xA9\xB5\xA0\x9A\x94\x0F\x03\x8D\x8D\xBCDa">,
 @signature=
  "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",
 @unencrypted_data=
  #<PedicelPay::TokenData:0x000000000213cb60
   @amount=63170,
   @cryptogram="HiQ1vFHOu7YWsQ==",
   @currency="417",
   @dm_id="07fb98b8b6",
   @eci="06",
   @expiry="190831",
   @name=nil,
   @pan="5767988526285104">,
 @version="EC_v1">
Your Apple Pay payment token:
{"data":"wXhKo9KTKs6+pzvq6xUM2EhAnEW08fprZVskYF7FOj7+/FN+8hKj4ZWSjNnjtjEEAiGonL/T9M7H2f7VOoyEcJJRURpnQZuoJtNjXsRT0sujEDcniiLpyajdcSTghXAjcAbuophvlOupPrqcDs8kH5fooMLu4Gjun4eahZi22gilNkUbRbXj5vABPIDx+RaGjuBQDgON+aMgL2YurblqbUqqQa7Tp68iH+PlXhV8rqD7wUQsnhzNYyVC7CeynoSAb5sjIoQ03Moap2O3ALFsPSu8Jh2enpnL27SsZxoTJTKjHC2YSRjPw70ttT278soTXyCDVGkeTl6ZwlhFNEElIKLAR81a0Ykny4PV0pSoo13acrhn4/zhlC5U7WpLerrj5nq56qTQQLrgJg94NSEgRrudMGw=","header":{"ephemeralPublicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdVHVUX2aojnisnb5xr/qa2OtlAkjFMdrS+e2w7XVKnZdG6lhx6KADDsEirfHaXmg6qBaF/rftekiwH7ZUsChhg==","publicKeyHash":"NbAOcxYJGFDg1I7JNdMFIYMMYV+E02ueUlYTPbArxb4=","transactionId":"b8f380f1b3cb7bde9cf7b881994e753da8a660bba9b5a09a940f038d8dbc4461"},"signature":"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","version":"EC_v1"}
Trust your newly generate root CA certificate:
{:oid_intermediate_certificate=>"1.2.840.113635.100.6.2.14",
 :oid_leaf_certificate=>"1.2.840.113635.100.6.29",
 :oid_merchant_identifier_field=>"1.2.840.113635.100.6.32",
 :replay_threshold_seconds=>180,
 :trusted_ca_pem=>
  "-----BEGIN CERTIFICATE-----\nMIICLTCCAdKgAwIBAgIBATAKBggqhkjOPQQDAjBtMQswCQYDVQQGEwJESzEVMBMG\nA1UECgwMUGVkaWNlbCBJbmMuMSgwJgYDVQQLDB9QZWRpY2VsIENlcnRpZmljYXRp\nb24gQXV0aG9yaXR5MR0wGwYDVQQDDBRQZWRpY2VsIFJvb3QgQ0EgLSBHMzAeFw0x\nNzAxMDEwMDAwMDBaFw0yMDAxMDEwMDAwMDBaMG0xCzAJBgNVBAYTAkRLMRUwEwYD\nVQQKDAxQZWRpY2VsIEluYy4xKDAmBgNVBAsMH1BlZGljZWwgQ2VydGlmaWNhdGlv\nbiBBdXRob3JpdHkxHTAbBgNVBAMMFFBlZGljZWwgUm9vdCBDQSAtIEczMFkwEwYH\nKoZIzj0CAQYIKoZIzj0DAQcDQgAE2LUF1OBUcwkby0+ySSvZoP6XBx5VXEVT177C\nzNUJuCsy3np72BdmpHFc92MMJgL0yDQhmhDp1/SrONlv6Mvq4aNjMGEwDwYDVR0T\nAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFHAKbEhcyhakbQPq\nYXpcSQ2oUy6PMB8GA1UdIwQYMBaAFHAKbEhcyhakbQPqYXpcSQ2oUy6PMAoGCCqG\nSM49BAMCA0kAMEYCIQCqBN3kVbe/ojZd7aIxtYTRQtZhUd96IiDDWQOweuKcSAIh\nAOltOrsSlHbVcn8Uo1NLcaoDwM0NEJ0x+TPTuKcycnqN\n-----END CERTIFICATE-----\n"}
Your decrypted data:
{"applicationPrimaryAccountNumber"=>"5767988526285104",
 "applicationExpirationDate"=>"190831",
 "currencyCode"=>"417",
 "transactionAmount"=>63170,
 "deviceManufacturerIdentifier"=>"07fb98b8b6",
 "paymentDataType"=>"3DSecure",
 "paymentData"=>
  {"onlinePaymentCryptogram"=>"HiQ1vFHOu7YWsQ==", "eciIndicator"=>"06"}}
```
