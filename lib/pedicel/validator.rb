require 'dry-validation'
require 'base64'

module Pedicel
  class Validator
    class Error < StandardError; end
    class TokenFormatError < Error; end
    class TokenDataFormatError < Error; end

    DRY_CUSTOM_PREDICATE_ERRORS = {
      base64?: 'invalid base64',
      hex?: 'invalid hex',
      pan?: 'invalid pan',
      yymmdd?: 'invalid date format YYMMDD',
    }

    module Predicates
      include Dry::Logic::Predicates

      predicate(:base64?) { |value| !Base64.decode64(value).nil? rescue false }

      predicate(:hex?) { |value| !Regexp.new(/\A[a-f0-9-]*\z/i).match(value).nil? }

      predicate(:pan?) { |value| !Regexp.new(/\A[0-9]{13,19}\z/).match(value).nil? }

      predicate(:yymmdd?) do |value|
        return false unless value.length == 6
        Time.new(value[0..1],value[2..3], value[4..5]).is_a?(Time) rescue false
      end
    end

    TokenSchema = Dry::Validation.Schema do
      configure do
        predicates(Predicates)
        def self.messages
          super.merge(en: { errors: DRY_CUSTOM_PREDICATE_ERRORS })
        end
      end

      required(:data).filled(:str?, :base64?)

      required(:header).schema do
        optional(:applicationData).filled(:str?, :hex?)

        optional(:ephemeralPublicKey).filled(:str?, :base64?)
        optional(:wrappedKey).filled(:str?, :base64?)
        rule('ephemeralPublicKey xor wrappedKey': [:ephemeralPublicKey, :wrappedKey]) do |e, w|
          e.filled? ^ w.filled?
        end

        required(:publicKeyHash).filled(:str?, :base64?)

        required(:transactionId).filled(:str?, :hex?)
      end

      required(:signature).filled(:str?, :base64?)

      required(:version).filled(:str?, included_in?: ['EC_v1', 'RSA_v1'])
    end

    # Pedicel::Validator::TokenSchema.call({data: 'asdf', header: {ephemeralPublicKey: 'e', publicKeyHash: 'p', transactionId: 'f'}, signature: 's', version: 'EC_v1'})

    TokenDataSchema = Dry::Validation.Schema do
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

      required(:paymentDataType).filled(:str?, included_in?: ['3DSecure', 'EMV'])

      required(:paymentData).schema do
        optional(:onlinePaymentCryptogram).filled(:str?, :base64?)
        optional(:eciIndicator).filled(:str?)

        optional(:emvData).filled(:str?, :base64?)
        optional(:encryptedPINData).filled(:str?, :hex?)
      end

      rule('consistent paymentDataType and paymentData': [:paymentDataType, [:paymentData, :onlinePaymentCryptogram]]) do |t, cryptogram|
        t.eql?('3DSecure') > cryptogram.filled?
      end
    end

    # Pedicel::Validator::TokenDataSchema.call(
    #   applicationPrimaryAccountNumber: '1234567890123',
    #   applicationExpirationDate: '101112',
    #   currencyCode: '123',
    #   transactionAmount: 12.34,
    #   cardholderName: 'asdf',
    #   deviceManufacturerIdentifier: 'adsf',
    #   paymentDataType: 'asdf',
    # )

    def self.validate_token(token, now: Time.now)
      validation = TokenSchema.call(token)

      raise TokenFormatError, validation.hints.map{|key,msg| "#{key} #{msg}"}.join(', and ') unless validation.errors.empty?

      true
    end

    def self.valid_token?(token, now: Time.now)
      validate_token(token, now: now) rescue false
    end

    def self.validate_token_data(token_data)
      validation = TokenDataSchema.call(token_data)

      raise TokenDataFormatError, validation.hints.map{|key,msg| "#{key} #{msg}"}.join(', and ') unless validation.errors.empty?

      true
    end

    def self.valid_token_data?(token_data)
      validate_token_data(token_data) rescue false
    end

    def validate_content(now: Time.now)
      raise ReplayAttackError, "token signature time indicates a replay attack (age #{now-cms_signing_time})" unless signing_time_ok?(now: now)

      raise SignatureError unless valid_signature?
    end
  end
end
