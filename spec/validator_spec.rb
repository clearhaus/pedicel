# frozen_string_literal: true

require 'pedicel'
require 'pedicel/validator'
require 'pedicel-pay'

require 'json'
require 'digest'

require 'pry'

module Pedicel
  class ValidationFactory
    def self.valid_token
      _, _, token = PedicelPay::Helper.generate_all
      token
    end

    def self.token_with_pan(pan)
      _, _, token = PedicelPay::Helper.generate_all(
        token_data: {
          pan: pan,
        }
      )
      token
    end
  end
end

# rubocop:disable Metrics/BlockLength
describe 'Pedicel::Validator.validate_token_data' do
  context 'with valid data' do
    it 'should validate' do
      data = Pedicel::ValidationFactory.valid_token.unencrypted_data

      expect(Pedicel::Validator.validate_token_data(data.to_hash)).to be true
      expect(Pedicel::Validator.valid_token_data?(data.to_hash)).to be true
    end
  end

  it 'should support shorthand notation' do
    expect(Pedicel::Validator.valid_token_data?({})).to be false
  end

  context 'with invalid pan' do
    it 'should reject if shorter than 12' do
      token = Pedicel::ValidationFactory.token_with_pan('24153681224')
                                        .unencrypted_data

      expect do
        Pedicel::Validator.validate_token_data(token.to_hash)
      end.to raise_error(Pedicel::Validator::TokenDataFormatError)
        .with_message(/applicationPrimaryAccountNumber.+invalid pan/i)
    end

    it 'should reject if longer than 19' do
      token = Pedicel::ValidationFactory.token_with_pan('24153681224518264891')
                                        .unencrypted_data

      expect do
        Pedicel::Validator.validate_token_data(token.to_hash)
      end.to raise_error(Pedicel::Validator::TokenDataFormatError)
        .with_message(/applicationPrimaryAccountNumber.+invalid pan/i)
    end

    it 'should reject if contains non-digits' do
      token = Pedicel::ValidationFactory.token_with_pan('122492765917264a')
                                        .unencrypted_data

      expect do
        Pedicel::Validator.validate_token_data(token.to_hash)
      end.to raise_error(Pedicel::Validator::TokenDataFormatError)
        .with_message(/applicationPrimaryAccountNumber.+invalid pan/i)
    end
  end

  it 'should reject if eciIndicator is not two digits' do
    %w[x1 1 231].each do |value|
      data = Pedicel::ValidationFactory.valid_token.unencrypted_data.to_hash
      data[:paymentData][:eciIndicator] = value

      expect do
        Pedicel::Validator.validate_token_data(data.to_hash)
      end.to raise_error(Pedicel::Validator::TokenDataFormatError)
        .with_message(/eciIndicator.+not an eci indicator/i)
    end
  end

  it 'should reject invalid time' do
    %w[11111 1111111 999999].each do |value|
      data = Pedicel::ValidationFactory.valid_token.unencrypted_data.to_hash
      data[:applicationExpirationDate] = value

      expect do
        Pedicel::Validator.validate_token_data(data.to_hash)
      end.to raise_error(Pedicel::Validator::TokenDataFormatError)
        .with_message(/applicationExpirationDate.+invalid date format/i)
    end
  end
end

describe 'Pedicel::Validator.validate_token' do
  context 'with valid token' do
    it 'should validate token' do
      token = Pedicel::ValidationFactory.valid_token

      token_hash = JSON.parse(token.to_json, symbolize_names: true)
      expect(Pedicel::Validator.validate_token(token.to_hash)).to be true

      expect(Pedicel::Validator.valid_token?(token_hash)).to be true
    end
  end

  it 'should support shorthand notation' do
    expect(Pedicel::Validator.valid_token?({})).to be false
  end

  context 'should check for base64, so' do
    it 'should fail on non base64-encoded text' do
      token = Pedicel::ValidationFactory.token_with_pan('24153681224').to_hash

      token['data'] = token['data'][0..-2]

      expect do
        Pedicel::Validator.validate_token(token)
      end.to raise_error(Pedicel::Validator::TokenFormatError)
        .with_message(/data.*invalid base64/i)
    end

    it 'should fail on non base64-encoded signature' do
      token = Pedicel::ValidationFactory.token_with_pan('24153681224').to_hash

      token['signature'] = token['signature'][0..-2]

      expect do
        Pedicel::Validator.validate_token(token)
      end.to raise_error(Pedicel::Validator::TokenFormatError)
        .with_message(/signature.*invalid base64/i)
    end

    it 'should fail on non base64-encoded ephemeralPublicKey' do
      token = Pedicel::ValidationFactory.token_with_pan('24153681224').to_hash

      token['header']['ephemeralPublicKey'] =
        token['header']['ephemeralPublicKey'][0..-2]

      expect do
        Pedicel::Validator.validate_token(token)
      end.to raise_error(Pedicel::Validator::TokenFormatError)
        .with_message(/ephemeralpublickey.+invalid base64/i)
    end

    it 'should fail on non base64-encoded publicKeyHash' do
      token = Pedicel::ValidationFactory.token_with_pan('24153681224').to_hash

      token['header']['publicKeyHash'] =
        token['header']['publicKeyHash'][0..-2]

      expect do
        Pedicel::Validator.validate_token(token)
      end.to raise_error(Pedicel::Validator::TokenFormatError)
        .with_message(/publicKeyHash.+invalid base64/i)
    end
  end

  context 'should check for hex encoding:' do
    it 'should fail for non-hex applicationData' do
      token = Pedicel::ValidationFactory.token_with_pan('24153681224').to_hash

      token['header']['applicationData'] = 'this is not hex-encoded'

      expect do
        Pedicel::Validator.validate_token(token)
      end.to raise_error(Pedicel::Validator::TokenFormatError)
        .with_message(/applicationData.+invalid hex/i)
    end

    it 'should fail for non-hex transactionId' do
      token = Pedicel::ValidationFactory.valid_token.to_hash

      token['header']['transactionId'] = 'this is very much not hex-encoded'

      expect do
        Pedicel::Validator.validate_token(token)
      end.to raise_error(Pedicel::Validator::TokenFormatError)
        .with_message(/transactionId.+invalid hex/i)
    end
  end

  context 'should check hashes:' do
    it 'should fail on non-sha256 applicationData' do
      token = Pedicel::ValidationFactory.valid_token.to_hash

      digest = Digest::SHA512.hexdigest 'Testing string'

      token['header']['applicationData'] = digest

      expect do
        Pedicel::Validator.validate_token(token)
      end.to raise_error(Pedicel::Validator::TokenFormatError)
        .with_message(/applicationData.+not hex-encoded SHA256/i)
    end

    it 'should succeed on sha256 applicationData' do
      token = Pedicel::ValidationFactory.valid_token.to_hash

      digest = Digest::SHA256.hexdigest 'Testing string'

      token['header']['applicationData'] = digest

      expect(Pedicel::Validator.valid_token?(token)).to be true
    end

    it 'should fail on non-sha256 publicKeyHash' do
      token = Pedicel::ValidationFactory.valid_token.to_hash

      digest = Digest::SHA512.base64digest 'Testing string'

      token['header']['publicKeyHash'] = digest

      expect do
        Pedicel::Validator.validate_token(token)
      end.to raise_error(Pedicel::Validator::TokenFormatError)
        .with_message(/publicKeyHash.+not base64-encoded SHA256/i)
    end

    it 'should fail on base64-encoded publicKeyHash that is too long' do
      token = Pedicel::ValidationFactory.valid_token.to_hash

      token['header']['publicKeyHash'] =
        Base64.strict_encode64(Random.new.bytes(33))

      expect do
        Pedicel::Validator.validate_token(token)
      end.to raise_error(Pedicel::Validator::TokenFormatError)
        .with_message(/publicKeyHash.+not base64-encoded sha256/i)
    end
  end

  it 'should fail if signature is not PKCS7' do
    token = Pedicel::ValidationFactory.valid_token.to_hash
    fakesig = Base64.strict_encode64('This is not a signature')
    token['signature'] = fakesig

    expect do
      Pedicel::Validator.validate_token(token)
    end.to raise_error(Pedicel::Validator::TokenFormatError)
      .with_message(/signature.+PKCS7/i)
  end

  it 'should fail if ephemeralPublicKey is not X.509 certificate' do
    token = Pedicel::ValidationFactory.valid_token.to_hash
    key = OpenSSL::PKey::RSA.new 4096

    token['header']['ephemeralPublicKey'] =
      Base64.strict_encode64(key.public_key.to_der)

    expect do
      Pedicel::Validator.validate_token(token)
    end.to raise_error(Pedicel::Validator::TokenFormatError)
      .with_message(/ephemeralPublicKey.+not a EC public key/i)
  end
end
# rubocop:enable Metrics/BlockLength
