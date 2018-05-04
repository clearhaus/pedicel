# frozen_string_literal: true

require 'dry-validation'
require 'base64'
require 'openssl'

module Pedicel
  # Validation class for Apple Pay Payment Token and associated data:
  # https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html
  # This purposefully only does syntactic validation (as opposed to semantic).
  class Validator
    class Error < StandardError; end
    class TokenFormatError < Error; end
    class TokenDataFormatError < Error; end

    DRY_CUSTOM_PREDICATE_ERRORS = {
      base64?: 'invalid base64',
      hex?: 'invalid hex',
      pan?: 'invalid pan',
      yymmdd?: 'invalid date format YYMMDD',
      ecPublicKey?: 'is not a EC public key',
      PKCS7Signature?: 'is not a PKCS7 Signature',
      ECI?: 'not an ECI indicator',
      hexsha256?: 'not hex-encoded SHA256',
      base64sha256?: 'not base64-encoded SHA256',
    }.freeze

    # Custom predicates for validation.
    # Some predicates statements have been unfolded for unit-testing purposes,
    # since _simplecov_ cannot check which branches have been used.
    module Predicates
      include Dry::Logic::Predicates

      predicate(:base64?) do |value|
        value.is_a?(String)
      end

      predicate(:hex?) do |value|
        if Regexp.new(/\A[a-f0-9]*\z/i).match(value).nil?
          false
        else
          true
        end
      end

      # Reference: https://en.wikipedia.org/wiki/Payment_card_number
      predicate(:pan?) do |value|
        if Regexp.new(/\A[0-9]{12,19}\z/).match(value).nil?
          false
        else
          true
        end
      end

      predicate(:yymmdd?) do |value|
        unless value.length == 6 # rubocop:disable Style/IfUnlessModifier
          return false
        end

        begin
          Time.new(value[0..1], value[2..3], value[4..5]).is_a?(Time)
        rescue
          false
        end
      end

      predicate(:ecPublicKey?) do |value|
        decoded = Base64.decode64(value)
        begin
          OpenSSL::PKey::EC.new(decoded).check_key
        rescue
          false
        end
      end

      predicate(:PKCS7Signature?) do |value|
        decoded = Base64.decode64(value)
        begin
          OpenSSL::PKCS7.new(decoded)
          true
        rescue
          false
        end
      end

      # Check if `value` is 2 digits.
      predicate(:ECI?) do |value|
        if !Regexp.new('\A\d{2}\z').match(value).nil?
          true
        else
          false
        end
      end

      # Check that length is 256bits, that is 64 hex digits.
      # Depends on :hex? check.
      predicate(:hexsha256?) do |value|
        if value.length == 64 # rubocop:disable Style/RedundantConditional
          true
        else
          false
        end
      end

      predicate(:base64sha256?) do |value|
        if value.length != 44
          false
        elsif !value.end_with?('=')
          false
        else
          true
        end
      end
    end

    TokenSchema = Dry::Validation.Schema do
      configure do
        # NOTE: This option removes/sanitizes hash element not mentioned/tested.
        # Hurray for good documentation.
        config.input_processor = :json

        # In theory, I would guess that :strict below would cause a failure if
        # untested keys were encountered, however this appears to not be the
        # case. Anyways, it's (of course) not documented.
        # config.hash_type = :strict

        predicates(Predicates)
        def self.messages
          super.merge(en: { errors: DRY_CUSTOM_PREDICATE_ERRORS })
        end
      end

      required(:data).filled(:str?, :base64?)

      required(:header).schema do
        optional(:applicationData).filled(:str?, :hex?, :hexsha256?)

        optional(:ephemeralPublicKey).filled(:str?, :base64?, :ecPublicKey?)
        optional(:wrappedKey).filled(:str?, :base64?)

        rule('ephemeralPublicKey xor wrappedKey':
             %i[ephemeralPublicKey wrappedKey]) do |e, w|
          e.filled? ^ w.filled?
        end

        required(:publicKeyHash).filled(:str?, :base64?, :base64sha256?)

        required(:transactionId).filled(:str?, :hex?)
      end

      required(:signature).filled(:str?, :base64?, :PKCS7Signature?)

      required(:version).filled(:str?, included_in?: %w[EC_v1 RSA_v1])
    end

    # rubocop:disable Metrics/BlockLength
    TokenDataSchema = Dry::Validation.Schema do
      # rubocop:enable Metrics/BlockLength

      configure do
        predicates(Predicates)
        def self.messages
          super.merge(en: { errors: DRY_CUSTOM_PREDICATE_ERRORS })
        end
      end

      required(:applicationPrimaryAccountNumber).filled(:str?, :pan?)

      required(:applicationExpirationDate).filled(:str?, :yymmdd?)

      required(:currencyCode).filled(:str?, format?: /\A[0-9]{3}\z/)

      required(:transactionAmount).filled(:int?)

      optional(:cardholderName).filled(:str?)

      required(:deviceManufacturerIdentifier).filled(:str?, :hex?)

      required(:paymentDataType).filled(:str?,
                                        included_in?: %w[3DSecure EMV])

      required(:paymentData).schema do
        optional(:onlinePaymentCryptogram).filled(:str?, :base64?)
        optional(:eciIndicator).filled(:str?, :ECI?)

        optional(:emvData).filled(:str?, :base64?)
        optional(:encryptedPINData).filled(:str?, :hex?)
      end

      rule(
        'paymentDataType affects paymentData':
         [:paymentDataType, %i[paymentData onlinePaymentCryptogram]]
      ) do |t, cryptogram|

        t.eql?('3DSecure') > cryptogram.filled?
      end
    end

    def self.validate_token(token)
      validation = TokenSchema.call(token)

      unless validation.success?
        raise TokenFormatError, format_errors(validation)
      end

      true
    end

    def self.valid_token?(token)
      validate_token(token)
    rescue
      false
    end

    def self.validate_token_data(token_data)
      validation = TokenDataSchema.call(token_data)

      unless validation.success?
        raise TokenDataFormatError, format_errors(validation)
      end

      true
    end

    def self.valid_token_data?(token_data)
      validate_token_data(token_data)
    rescue
      false
    end

    def self.format_errors(validation)
      validation.errors.map { |key, msg| "#{key}: #{msg}\n" }
                .join(', and ')
    end
  end
end
