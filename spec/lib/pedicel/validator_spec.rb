require 'pedicel/validator'
require 'pedicel-pay'

require 'json'
require 'digest'

valid_ec_public_key = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0wzW/i0nT3XOeo6srobJRGnUlmqGTFahuHEOw4M9nxUlTBaQUNc8HlN/z1HbepGXTZWDSJB2deCGfhsrOdVryQ=='

describe Pedicel::Validator do
  let (:token) do
    backend = PedicelPay::Backend.generate
    client = backend.generate_client

    token = PedicelPay::Token.new.sample
    backend.encrypt_and_sign(token, recipient: client)

    token
  end

  describe Pedicel::Validator::Token do
    let(:validator) { Pedicel::Validator::Token.new(token.to_hash) }

    describe '#valid?' do
      it 'relies on #validate' do
        return_value = 'return_value'
        expect(validator).to receive(:validate).and_return(return_value)
        expect(validator.valid?).to equal return_value
      end
    end

    describe '#validate' do
      context 'can be happy' do
        subject { lambda { validator.validate } }

        it 'does not err on a valid token' do
          is_expected.to_not raise_error
        end

        it 'is truthy for a valid token' do
          expect(validator.validate).to be_truthy
        end
      end

      let(:token_h) { token.to_hash }
      let(:validator) { Pedicel::Validator::Token.new(token_h) }
      subject { lambda { validator.validate } }
      let(:e) { validator.errors.to_s }

      context 'wrong data' do
        it 'errs when data is missing' do
          token_h.delete('data')
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to match(/data.*missing/)
        end

        it 'errs when data is not a string' do
          token_h['data'] = [1,2,3]
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to match(/data.*must be a string/)

          token_h['data'] = { :'a string as a hash key' => 'a string in a hash value' }
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to match(/data.*must be a string/)
        end

        it 'errs when data is not Base64' do
          token_h['data'] = '%'
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to match(/data.*base64/)
        end
      end

      context 'signature' do
        it 'errs when invalid' do
          token_h['signature'] = 'invalid signature'
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to include('signature')
        end

        it 'errs when missing' do
          token_h.delete('signature')
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to match(/signature.*missing/)
        end

        it 'errs when not a string' do
          token_h['signature'] = 123
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to match(/signature.*must be a string/)
        end

        it 'errs when not a hex string' do
          token_h['signature'] = 'not hex'
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to match(/signature.*must be base64/)
        end
      end

      context 'version' do
        it 'errs when invalid' do
          token_h['version'] = 'invalid version'
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to include('version')
        end

        it 'errs when missing' do
          token_h.delete('version')
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to match(/version.*missing/)
        end

        it 'errs when not a strign' do
          token_h['version'] = 123
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to match(/version.*must be a string/)
        end

        it 'errs when not a supported version' do
          token_h['version'] = 'EC_v0'
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to match(/version.*must be one of/)
        end
      end

      context 'header' do
        let (:header_h) { token_h['header'] }

        it 'errs when missing' do
          token_h.delete('header')
          is_expected.to raise_error(Pedicel::Validator::Token::Error)
          expect(e).to match(/header.*missing/)
        end

        it 'errs when not a hash' do
          ['asdf', [], 123].each do |invalid|
            token_h['header'] = invalid
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/header.*hash/)
          end
        end

        context 'applicationData' do
          it 'errs when invalid' do
            header_h['applicationData'] = 'invalid applicationData'
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to include('applicationData')
          end

          it 'does not err when missing' do
            header_h.delete('applicationData')
            is_expected.to_not raise_error
          end

          it 'errs when not a string' do
            header_h['applicationData'] = 123
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/applicationData.*must be a string/)
          end

          it 'errs when not a hex string' do
            header_h['applicationData'] = 'not hex'
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/applicationData.*must be hex/)
          end
        end

        context 'ephemeralPublicKey' do
          it 'errs when invalid' do
            header_h['ephemeralPublicKey'] = 'invalid ephemeralPublicKey'
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to include('ephemeralPublicKey')
          end
          it 'errs when not a string' do
            header_h['ephemeralPublicKey'] = 123
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/ephemeralPublicKey.*must be a string/)
          end

          it 'errs when not Base64' do
            header_h['ephemeralPublicKey'] = '%'
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/ephemeralPublicKey.*must be base64/)
          end

          it 'errs when invalid EC public key' do
            header_h['ephemeralPublicKey'] = 'validBase64ButInvalidEcPublicKey'
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/ephemeralPublicKey.*EC public key/)
          end
        end

        context 'wrappedKey' do
          it 'errs when invalid' do
            header_h['wrappedKey'] = 'invalid wrappedKey'
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/wrappedKey.*must be/)
          end

          it 'errs when not a string' do
            header_h['wrappedKey'] = 123
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/wrappedKey.*must be a string/)
          end
        end

        context 'consistency among ephemeralPublicKey and wrappedKey' do
          it 'errs when both are present' do
            header_h['ephemeralPublicKey'] = valid_ec_public_key
            header_h['wrappedKey'] = 'validbase64='
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to include('xor')
          end

          it 'errs when neither are present' do
            header_h.delete('ephemeralPublicKey')
            header_h.delete('wrappedKey')
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to include('xor')
          end

          it 'does not err when only ephemeralPublicKey is present' do
            header_h['ephemeralPublicKey'] = valid_ec_public_key
            header_h.delete('wrappedKey')
            is_expected.to_not raise_error
          end

          it 'does not err when only wrappedKey is present' do
            header_h.delete('ephemeralPublicKey')
            header_h['wrappedKey'] = 'validbase64='
            is_expected.to_not raise_error
          end
        end

        context 'publicKeyHash' do
          it 'errs when invalid' do
            header_h['publicKeyHash'] = 'invalid publicKeyHash'
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to include('publicKeyHash')
          end

          it 'errs when missing' do
            header_h.delete('publicKeyHash')
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/publicKeyHash.*missing/)
          end

          it 'errs when not a string' do
            header_h['publicKeyHash'] = 123
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/publicKeyHash.*must be a string/)
          end

          it 'errs when not Base64' do
            header_h['publicKeyHash'] = '%'
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/publicKeyHash.*must be base64/)
          end
        end

        context 'transactionId' do
          it 'errs when invalid' do
            header_h['transactionId'] = 'invalid transactionId'
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to include('transactionId')
          end

          it 'errs when missing' do
            header_h.delete('transactionId')
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/transactionId.*missing/)
          end

          it 'errs when not a string' do
            header_h['transactionId'] = 123
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/transactionId.*must be a string/)
          end

          it 'errs when not a hex string' do
            header_h['transactionId'] = 'not hex'
            is_expected.to raise_error(Pedicel::Validator::Token::Error)
            expect(e).to match(/transactionId.*must be hex/)
          end
        end
      end
    end
  end

  describe Pedicel::Validator::TokenData do
    let(:token_data_h) { JSON.parse(token.unencrypted_data.to_hash.to_json) }
    let(:validator) { Pedicel::Validator::TokenData.new(token_data_h) }
    let(:e) { validator.errors.to_s }

    describe '#valid?' do
      it 'relies on #validate' do
        return_value = 'return_value'
        expect(validator).to receive(:validate).and_return(return_value)
        expect(validator.valid?).to equal return_value
      end
    end

    describe '#validate' do
      subject { lambda { validator.validate } }

      context 'can be happy' do
        it 'does not err on valid token data' do
          is_expected.to_not raise_error
        end

        it 'is true for valid token data' do
          expect(validator.validate).to be true
        end
      end

      context 'wrong data' do
        [
          'applicationPrimaryAccountNumber',
          'applicationExpirationDate',
          'currencyCode',
          'transactionAmount',
          'deviceManufacturerIdentifier',
          'paymentDataType',
          'paymentData',
        ].each do |required_key|
          it "errs when #{required_key} is missing" do
            token_data_h.reject!{|key, _| key == required_key}

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/#{required_key}.*is missing/)
          end
        end

        [
          'applicationPrimaryAccountNumber',
          'applicationExpirationDate',
          'currencyCode',
          'cardholderName',
          'deviceManufacturerIdentifier',
          'paymentDataType',
        ].each do |string_key|
          it "errs when #{string_key} is not a string" do
            token_data_h.merge!(string_key => 42)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/#{string_key}.*must be a string/)
          end
        end

        [
          'onlinePaymentCryptogram',
          'eciIndicator',
          'emvData',
          'encryptedPINData',
        ].each do |payment_data_string_key|
          it "errs when #{payment_data_string_key} is not a string" do
            token_data_h['paymentData'].merge!(payment_data_string_key => 42)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/#{payment_data_string_key}.*must be a string/)
          end
        end

        it 'errs when applicationPrimaryAccountNumber is not a PAN' do
          [
            '0123123412341234',
            '1234567890',
            '12345678901234567890',
            '1234A23412341234',
          ].each do |invalid_value|
            token_data_h.merge!('applicationPrimaryAccountNumber' => invalid_value)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/applicationPrimaryAccountNumber.*must be a pan/)
          end
        end

        it 'errs when applicationExpirationDate is not a date' do
          %w(12345 1234567 1A3456).each do |invalid_value|
            token_data_h.merge!('applicationExpirationDate' => invalid_value)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/applicationExpirationDate.*must be formatted YYMMDD/)
          end
        end

        it 'errs when currencyCode is not a currency code' do
          %w(11 11A 1111).each do |invalid_value|
            token_data_h.merge!('currencyCode' => invalid_value)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/currencyCode.*must be an ISO 4217 numeric code/)
          end
        end

        it 'errs when transactionAmount is not an integer' do
          [
            'abc',
            '42',
            [42],
            { abc: 42 },
            { 'abc' => 42 },
            true,
          ].each do |invalid_value|
            token_data_h.merge!('transactionAmount' => invalid_value)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/transactionAmount.*must be an integer/)
          end
        end

        it 'errs when deviceManufacturerIdentifier is not hex' do
          %w(42-42 42Z).each do |invalid_value|
            token_data_h.merge!('deviceManufacturerIdentifier' => invalid_value)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/deviceManufacturerIdentifier.*must be hex/)
          end
        end

        it 'errs when encryptedPINData is not hex' do
          %w(42-42 42Z).each do |invalid_value|
            token_data_h['paymentData'].merge!('encryptedPINData' => invalid_value)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/encryptedPINData.*must be hex/)
          end
        end

        it 'errs when paymentDataType is unsupported' do
          %w(3dsecure emv 3D Secure 3DSecure2 EMVCo).each do |invalid_value|
            token_data_h.merge!('paymentDataType' => invalid_value)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/paymentDataType.*must be one of: 3DSecure, EMV/)
          end
        end

        it 'errs when onlinePaymentCryptogram is not base64' do
          %w(% fooo= f===).each do |invalid_value|
            token_data_h['paymentData'].merge!('onlinePaymentCryptogram' => invalid_value)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/onlinePaymentCryptogram.*must be base64/)
          end
        end

        it 'errs when emvData is not base64' do
          %w(% fooo= f===).each do |invalid_value|
            token_data_h['paymentData'].merge!('emvData' => invalid_value)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/emvData.*must be base64/)
          end
        end

        it 'errs when eciIndicator is invalid' do
          %w(1 123 1A).each do |invalid_value|
            token_data_h['paymentData'].merge!('eciIndicator' => invalid_value)

            is_expected.to raise_error(Pedicel::Validator::TokenData::Error)
            expect(e).to match(/eciIndicator.*must be an ECI/)
          end
        end
      end
    end
  end
end

describe Pedicel::Validator::Predicates do
  describe '.base64?' do
    def base64?(x); subject.base64?(x); end

    it 'true for valid Base64' do
      expect(base64?('')).to eq(true)
      expect(base64?('validbase64=')).to eq(true)
    end

    it 'false for invalid Base64' do
      expect(base64?(nil)).to be false
      expect(base64?('%')).to be false
      expect(base64?('fooo=')).to be false
      expect(base64?('f===')).to be false
    end
  end

  describe '.base64_sha256?' do
    def base64_sha256?(x); subject.base64_sha256?(x); end

    it "true for valid Base64 encoded SHA-256's" do
      expect(base64_sha256?('0byNO6Svx+EJYSy3Osvd2sBSyTAlqh+ClC7au33rgqE=')).to be true
      expect(base64_sha256?('0000000000000000000000000000000000000000000=')).to be true
      expect(base64_sha256?('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=')).to be true
      expect(base64_sha256?('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=')).to be true
    end

    it 'uses base64? predicate and is non-strictly evaluating if it is a SHA-256' do
      expect(subject).to receive(:base64?).and_return(true)
      # Non-strict test: should ignore the extra ='s since the above stub allows anything.
      expect(base64_sha256?('0000000000000000000000000000000000000000000======')).to be true

      expect(subject).to receive(:base64?).and_return(false)
      expect(base64_sha256?('0000000000000000000000000000000000000000000=')).to be false
    end

    it 'false for non-SHA-256 that are Base64 encoded' do
      expect(base64_sha256?('too short')).to be false
      expect(base64_sha256?("t#{'o'*50} long")).to be false
    end
  end

  describe '.hex?' do
    def hex?(x); subject.hex?(x); end

    it 'true for a hex string' do
      expect(hex?('')).to be true
      expect(hex?(['a'..'f', 'A'..'F', 0..9].map(&:to_a).inject(&:concat).join)).to be true
    end

    it 'false for non-Hex characters' do
      expect(hex?('g')).to be false
      expect(hex?('G')).to be false
      expect(hex?('_')).to be false
      expect(hex?(' ')).to be false
      expect(hex?('/')).to be false
    end
  end

  describe '.hex_sha256?' do
    def hex_sha256?(x); subject.hex_sha256?(x); end

    it "true for valid hex encoded SHA-256's" do
      expect(hex_sha256?('d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1')).to be true
      expect(hex_sha256?('D1BC8D3BA4AFC7E109612CB73ACBDDDAC052C93025AA1F82942EDABB7DEB82A1')).to be true
      expect(hex_sha256?('d1bc8d3ba4afc7e109612cb73acbdddAC052C93025AA1F82942EDABB7DEB82A1')).to be true
    end

    it 'uses hex? predicate' do
      expect(subject).to receive(:hex?).and_return(true)
      expect(hex_sha256?('XYZc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb8XYZ')).to be true
      # Should only care about the length when hex? has ensured that it is hex.

      expect(subject).to receive(:hex?).and_return(false)
      expect(hex_sha256?('d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1')).to be false
    end

    it 'false for non-SHA-256 that are hex encoded' do
      expect(hex_sha256?('aedf')).to be false
      expect(hex_sha256?('1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1')).to be false
      expect(hex_sha256?('Fd1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1')).to be false
    end
  end

  describe '.pan?' do
    def pan?(x); subject.pan?(x); end

    it 'true for valid PANs' do
      expect(pan?('123456789012')).to be true
      expect(pan?('1234567890123456789')).to be true
      expect(pan?('1234567890123456')).to be true
      expect(pan?('1000000000000000')).to be true
    end

    it 'false if PAN contains anything but digits' do
      expect(pan?('1a34567890123456')).to be false
      expect(pan?('1 34567890123456')).to be false
      expect(pan?('1_34567890123456')).to be false
      expect(pan?('134567890123456 ')).to be false
      expect(pan?(' 134567890123456')).to be false
    end

    it 'false if PAN starts with a zero' do
      expect(pan?('0234567890123456')).to be false
    end

    it 'false if PAN is shorter than 12 digits' do
      expect(pan?('12345678901')).to be false
    end

    it 'false if PAN is longer than 19 digits' do
      expect(pan?('12345678901234567890')).to be false
    end
  end

  describe '.yymmdd?' do
    def yymmdd?(x); subject.yymmdd?(x); end

    it 'is true for valid dates' do
      expect(yymmdd?('180228')).to be true
      expect(yymmdd?('200229')).to be true
    end

    it 'is true for invalid dates that are still date-like' do
      expect(yymmdd?('170229')).to be true
      expect(yymmdd?('179901')).to be true
    end

    it 'is false for non-numeric "dates"' do
      expect(yymmdd?('17ja19')).to be false
    end
  end

  describe '.eci?' do
    def eci?(x); subject.eci?(x); end

    it 'is true for valid ECIs' do
      expect(eci?('05')).to be true
      expect(eci?('06')).to be true
      expect(eci?('07')).to be true
    end

    it 'is false for ECIs of wrong length' do
      expect(eci?('005')).to be false
      expect(eci?('5')).to   be false
      expect(eci?(' 05')).to be false
    end

    it 'is false for non-numeric ECIs' do
      expect(eci?('  ')).to be false
      expect(eci?('ab')).to be false
      expect(eci?('__')).to be false
    end
  end

  describe '.ec_public_key?' do
    def ec_public_key?(x); subject.ec_public_key?(x); end

    it 'is true for valid EC public keys' do
      expect(ec_public_key?(valid_ec_public_key)).to be true
    end

    it 'is false for invalid EC public keys' do
      expect(ec_public_key?('validBase64ButInvalidEcPublicKey')).to be false
    end

    it 'uses base64? predicate to ensure that it is Base64' do
      expect(subject).to receive(:base64?).and_return(false)
      expect(ec_public_key?('validbase64=')).to be false
    end
  end

  describe '.pkcs7_signature?' do
    def pkcs7_signature?(x); subject.pkcs7_signature?(x); end

    it 'is true for valid PKCS7 signatures' do
      valid_signature = <<~PEM
        MIIKRwYJKoZIhvcNAQcCoIIKODCCCjQCAQExDzANBglghkgBZQMEAgEFADCC
        AcIGCSqGSIb3DQEHAaCCAbMEggGvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
        QgAE/2KR0tgjCI8ImkM1/EU+G0Lkvvty7iU5LMc0tUmMw/oAAUaszKlUYZ+K
        3Nq6PwywyHLtr0ghpFJRDMslm3Fj264IocefXqQue93zm7qPdnyHLKzMuX9u
        sJv8RLSivYB/EkumLwHeWJPIdb7jcVsV0qSuiOTOj3blEs4MJfO8cpGag0Nn
        Eh6twRaAfnioiVn0g1jXEsi8oul7OIATJj8gsYJvTyom95eq9yYQYDl9ITAd
        5rLrJ9oNxkR0G+tK7aDexnhBdBpQQPdLKQ4PJc009CBZlIe0ozMb/ubByoIf
        IAmc2KGPUpsLN/+m1Q9LkIKFo78Zq/18/jvq2GO527yfq+7AuV1LQBOo5Mbm
        Wh+sIWv964ix8iiCF13TrPaGC6AILM1rE2ZJQY/gicL6LK5s4ti61TP/Xc7s
        Fq6bb5Na/I4LjDdGCoaZ3gyuuzzfbFg3tKUlAlti0gcOVRVl956oqRsgMnKH
        QyUxMkV4SM6A+HEPfINMB/FB6FMG9lElUVm3vHkbqCozAQLKkWupxO7sGvy+
        92CgggZ4MIICETCCAbegAwIBAgIBATAKBggqhkjOPQQDAjCBgDELMAkGA1UE
        BhMCREsxFTATBgNVBAoMDFBlZGljZWwgSW5jLjEoMCYGA1UECwwfUGVkaWNl
        bCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEwMC4GA1UEAwwnUGVkaWNlbCBB
        cHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSAtIEczMB4XDTE3MDEwMTAwMDAw
        MFoXDTIwMDEwMTAwMDAwMFowYTELMAkGA1UEBhMCREsxFTATBgNVBAoMDFBl
        ZGljZWwgSW5jLjEUMBIGA1UECwwLcE9TIFN5c3RlbXMxJTAjBgNVBAMMHGVj
        Yy1zbXAtYnJva2VyLXNpZ25fVUM0LVBST0QwWTATBgcqhkjOPQIBBggqhkjO
        PQMBBwNCAATF6GdRK7PsiDtSlPTejnXsDLKn6ILhJgqIm8LxwPUgCXTUAhO3
        Mbn/Y8T0xK83eFTdT5oRY08fWM4JmoVAenpwo0AwPjAOBgNVHQ8BAf8EBAMC
        B4AwHQYDVR0OBBYEFHfPaCMkdecS4AgH0nc6gUZJJ5u6MA0GCSqGSIb3Y2QG
        HQQAMAoGCCqGSM49BAMCA0gAMEUCICtpCs+aQ1jQ3u12D0u/hstij1PAOP0A
        /GMYnDpeEQ8EAiEA+7bj8qm4B3O43Ll8IdwyKza2oiVrw3Ch8cEpV6mM0UMw
        ggIuMIIB1aADAgECAgEBMAoGCCqGSM49BAMCMG0xCzAJBgNVBAYTAkRLMRUw
        EwYDVQQKDAxQZWRpY2VsIEluYy4xKDAmBgNVBAsMH1BlZGljZWwgQ2VydGlm
        aWNhdGlvbiBBdXRob3JpdHkxHTAbBgNVBAMMFFBlZGljZWwgUm9vdCBDQSAt
        IEczMB4XDTE3MDEwMTAwMDAwMFoXDTIwMDEwMTAwMDAwMFowgYAxCzAJBgNV
        BAYTAkRLMRUwEwYDVQQKDAxQZWRpY2VsIEluYy4xKDAmBgNVBAsMH1BlZGlj
        ZWwgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxMDAuBgNVBAMMJ1BlZGljZWwg
        QXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgLSBHMzBZMBMGByqGSM49AgEG
        CCqGSM49AwEHA0IABASlf05UCs7jmvfRv0rhmqhTNAAZIk91T+k/mE1rho/X
        2ET7Kx3hkNNYZ0auWym//EIC9StVdz6LcNwZOijaiJejUjBQMA8GA1UdEwEB
        /wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTT8DLx2cuH85ZO
        vjMJjiAxPf7IPDAOBgoqhkiG92NkBgIOBAAwCgYIKoZIzj0EAwIDRwAwRAIg
        AvtOT6CCV2O/bumwzY9S4Px4GHpPSFeuJJwPzVX8BbACIFDXkjBMyHRXrhLe
        PhQNh1gH18X+8VINbLE2b26TrunFMIICLTCCAdOgAwIBAgICAsIwCgYIKoZI
        zj0EAwIwbTELMAkGA1UEBhMCREsxFTATBgNVBAoMDFBlZGljZWwgSW5jLjEo
        MCYGA1UECwwfUGVkaWNlbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEdMBsG
        A1UEAwwUUGVkaWNlbCBSb290IENBIC0gRzMwHhcNMTcwMTAxMDAwMDAwWhcN
        MjAwMTAxMDAwMDAwWjBtMQswCQYDVQQGEwJESzEVMBMGA1UECgwMUGVkaWNl
        bCBJbmMuMSgwJgYDVQQLDB9QZWRpY2VsIENlcnRpZmljYXRpb24gQXV0aG9y
        aXR5MR0wGwYDVQQDDBRQZWRpY2VsIFJvb3QgQ0EgLSBHMzBZMBMGByqGSM49
        AgEGCCqGSM49AwEHA0IABDp+ySLHlsaSkmIN9vqiPom0O7SKPvf5UWB2zQ99
        avfHYFTLeW51+Or4/X/r6MakSAVVvaEDOmi7rQYrga98zSSjYzBhMA8GA1Ud
        EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRXxyoMIIml
        dfCobWDa0R1VhU012DAfBgNVHSMEGDAWgBRXxyoMIImldfCobWDa0R1VhU01
        2DAKBggqhkjOPQQDAgNIADBFAiEA1PAFBb7d2UEvZSQy2FP8IDE+MX6tSDD2
        sB+FQPIgkRgCIAJSb3Je7poRVDyABU47f8tuBCrX9fxIvkl7JfpXmhCDMYIB
        2jCCAdYCAQEwgYYwgYAxCzAJBgNVBAYTAkRLMRUwEwYDVQQKDAxQZWRpY2Vs
        IEluYy4xKDAmBgNVBAsMH1BlZGljZWwgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
        dHkxMDAuBgNVBAMMJ1BlZGljZWwgQXBwbGljYXRpb24gSW50ZWdyYXRpb24g
        Q0EgLSBHMwIBATANBglghkgBZQMEAgEFAKCB5DAYBgkqhkiG9w0BCQMxCwYJ
        KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xODA1MDQwOTE3NTdaMC8GCSqG
        SIb3DQEJBDEiBCBYcUX4dnxfr+/Y7v+JENQUa7Fw7uXxUD/mOIs+ccXRCjB5
        BgkqhkiG9w0BCQ8xbDBqMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
        YIZIAWUDBAECMAoGCCqGSIb3DQMHMA4GCCqGSIb3DQMCAgIAgDANBggqhkiG
        9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0DAgIBKDAKBggqhkjOPQQDAgRG
        MEQCIAeueGU9HiDaNkFRlQJT/6bv5CYtyF2MPHdeMNIRZIjDAiBYCW0KdJNa
        DwLe7kuv8fxkKXVwBJgZlD3MdHtONCrzVQ==
      PEM
      valid_signature.gsub!(/\s/, '')

      expect(pkcs7_signature?(valid_signature)).to be true
    end

    it 'is false for invalid PKCS7 signatures' do
      expect(pkcs7_signature?('validbase64=')).to be false
    end

    it 'uses base64? predicate to ensure that it is Base64' do
      expect(subject).to receive(:base64?).and_return(false)
      expect(pkcs7_signature?('validbase64=')).to be false
    end
  end
end
