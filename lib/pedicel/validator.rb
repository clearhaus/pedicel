require 'dry/validation'
require 'dry/schema'
require 'dry/logic'
require 'base64'
require 'openssl'

module Pedicel

  # Validations for Apple Pay Payment Token and associated data:
  # https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html
  # This purposefully only does syntactic validation (as opposed to semantic).
  module Validator
    CUSTOM_ERRORS = {
      is_base64:          'must be Base64',
      is_hex:             'must be hex',
      is_pan:             'must be a pan',
      is_yymmdd:          'must be formatted YYMMDD',
      is_ec_public_key:   'must be an EC public key',
      is_pkcs7_signature: 'must be a PKCS7 Signature',
      is_eci:             'must be an ECI',
      is_hex_sha256:      'must be a hex-encoded SHA-256',
      is_base64_sha256:   'must be a Base64-encoded SHA-256',
      is_iso4217_numeric: 'must be an ISO 4217 numeric code',
    }.freeze

    Dry::Validation.register_macro(:is_hex) do
      if key?
        unless /\A[a-f0-9]*\z/i.match?(value)
          key.failure(CUSTOM_ERRORS[:is_hex])
        end
      end
    end

    Dry::Validation.register_macro(:is_hex_sha256) do
      if key?
        unless :is_hex && value.length == 64
          key.failure(CUSTOM_ERRORS[:is_hex_sha256])
        end
      end
    end

    Dry::Validation.register_macro(:is_base64) do
      if key?
        unless /\A[=A-Za-z0-9+\/]*\z/.match?(value) &&
               value.length.remainder(4).zero? &&
               !/=[^$=]/.match?(value) &&
               !/===/.match?(value)
          key.failure(CUSTOM_ERRORS[:is_base64])
        end
      end
    end

    Dry::Validation.register_macro(:is_base64_sha256) do
      if key?
        unless :is_base64 && Base64.decode64(value).length == 32
          key.failure(CUSTOM_ERRORS[:is_base64_sha256])
        end
      end
    end

    Dry::Validation.register_macro(:is_ec_public_key) do
      if key?
        ec = lambda {OpenSSL::PKey::EC.new(Base64.decode64(value)).check_key rescue false}.()
        unless :is_base64 && ec
          key.failure(CUSTOM_ERRORS[:is_ec_public_key])
        end
      end
    end

    Dry::Validation.register_macro(:is_pkcs7_signature) do
      if key?
        ec = lambda {!!OpenSSL::PKCS7.new(Base64.decode64(value)) rescue false}.()
        unless :is_base64 && ec
          key.failure(CUSTOM_ERRORS[:is_pkcs7_signature])
        end
      end
    end

    Dry::Validation.register_macro(:is_eci) do
      if key?
        unless  /\A\d{1,2}\z/.match?(value)
          key.failure(CUSTOM_ERRORS[:is_eci])
        end
      end
    end

    Dry::Validation.register_macro(:is_pan) do
      if key?
        unless  /\A[1-9][0-9]{11,18}\z/.match?(value)
          key.failure(CUSTOM_ERRORS[:is_pan])
        end
      end
    end

    Dry::Validation.register_macro(:is_yymmdd) do
      if key?
        unless  /\A\d{6}\z/.match?(value)
          key.failure(CUSTOM_ERRORS[:is_yymmdd])
        end
      end
    end

    Dry::Validation.register_macro(:is_iso4217_numeric) do
      if key?
        unless  /\A[0-9]{3}\z/.match?(value)
          key.failure(CUSTOM_ERRORS[:is_iso4217_numeric])
        end
      end
    end

    class TokenHeaderSchemaKlass < Dry::Validation::Contract
      json do
        optional(:applicationData).filled(:str?)

        optional(:ephemeralPublicKey).filled(:str?)

        optional(:wrappedKey).filled(:str?)


        required(:publicKeyHash).filled(:str?)
        required(:transactionId).filled(:str?)
      end
      rule(:applicationData).validate(:is_hex, :is_hex_sha256)

      rule(:ephemeralPublicKey).validate(:is_base64, :is_ec_public_key)
      rule(:publicKeyHash).validate(:is_base64, :is_base64_sha256)
      rule(:wrappedKey).validate(:is_base64)
      rule(:transactionId).validate(:is_hex)
      rule(:ephemeralPublicKey, :wrappedKey) do
        key.failure('ephemeralPublicKey xor wrappedKey') unless values[:ephemeralPublicKey].nil? ^ values[:wrappedKey].nil?
      end
    end

    TokenHeaderSchema = TokenHeaderSchemaKlass.new

    class TokenContract < Dry::Validation::Contract
      json do
        required(:data).filled(:str?)

        required(:header).schema(TokenHeaderSchemaKlass.schema)
        required(:header).value(:hash?)

        required(:signature).filled(:str?)

        required(:version).filled(:str?, included_in?: %w[EC_v1 RSA_v1])

      end
      rule(:data).validate(:is_base64)
      rule(:signature).validate(:is_base64, :is_pkcs7_signature)
    end

    TokenSchema = TokenContract.new

    class TokenDataPaymentDataContract < Dry::Validation::Contract
      json do
        optional(:onlinePaymentCryptogram).filled(:str?)
        optional(:eciIndicator).filled(:str?)

        optional(:emvData).filled(:str?)
        optional(:encryptedPINData).filled(:str?)
      end
      rule(:onlinePaymentCryptogram).validate(:is_base64)
      rule(:eciIndicator).validate(:is_eci)

      rule(:emvData).validate(:is_base64)
      rule(:encryptedPINData).validate(:is_hex)
    end

    TokenDataPaymentDataSchema = TokenDataPaymentDataContract.new

    class TokenDataContract < Dry::Validation::Contract
      json do
        required(:applicationPrimaryAccountNumber).filled(:str?)

        required(:applicationExpirationDate).filled(:str?)

        required(:currencyCode).filled(:str?)

        required(:transactionAmount).filled(:int?)

        optional(:cardholderName).filled(:str?)

        required(:deviceManufacturerIdentifier).filled(:str?)

        required(:paymentDataType).filled(:str?, included_in?: %w[3DSecure EMV])

        required(:paymentData).schema(TokenDataPaymentDataContract.schema)
      end
      rule(:applicationPrimaryAccountNumber).validate(:is_pan)

      rule(:applicationExpirationDate).validate(:is_yymmdd)

      rule(:currencyCode).validate(:is_iso4217_numeric)

      rule(:deviceManufacturerIdentifier).validate(:is_hex)

      rule(:paymentDataType, paymentData: :onlinePaymentCryptogram) do
        # rule('when paymentDataType is 3DSecure, onlinePaymentCryptogram': [:paymentDataType, [:paymentData, :onlinePaymentCryptogram]]) do |type, cryptogram|
        #   type can only be 3DSecure if cryptogram is filled
        #   type.eql?('3DSecure') > cryptogram.filled?
        # end
        if values[:paymentDataType].eql?('3DSecure')
          key.failure('when paymentDataType is 3DSecure, onlinePaymentCryptogram must be filled') unless
            values[:paymentData] && values[:paymentData][:onlinePaymentCryptogram]
        end
      end

      rule(:paymentDataType, paymentData: :emvData) do
        # type can only be 3DSecure if emvData is empty
        # old rule:
        # rule('when paymentDataType is 3DSecure, emvData': [:paymentDataType, [:paymentData, :emvData]]) do |type, emv|
        #   type.eql?('3DSecure') > emv.none?
        # end
        if values[:paymentDataType].eql?('3DSecure')
          key.failure('when paymentDataType is 3DSecure, emvData cannot be defined') unless
            values[:paymentData] && values[:paymentData][:emvData].nil?
        end
      end

      rule(:paymentDataType, paymentData: :encryptedPINData) do
        # type can only be 3DSecure if emvData is empty
        # old rule:
        # rule('when paymentDataType is 3DSecure, encryptedPINData': [:paymentDataType, [:paymentData, :encryptedPINData]]) do |type, pin|
        #   type.eql?('3DSecure') > pin.none?
        # end
        if values[:paymentDataType].eql?('3DSecure')
          key.failure('when paymentDataType is 3DSecure, encryptedPINData cannot be defined') unless
            values[:paymentData] && values[:paymentData][:encryptedPINData].nil?
        end
      end

      rule(:paymentDataType, paymentData: :onlinePaymentCryptogram) do
        # type can only be 3DSecure if emvData is empty
        # old rule:
        # rule('when paymentDataType is EMV, onlinePaymentCryptogram': [:paymentDataType, [:paymentData, :onlinePaymentCryptogram]]) do |type, cryptogram|
        #   type.eql?('EMV') > cryptogram.none?
        # end
        if values[:paymentDataType].eql?('EMV')
          key.failure('when paymentDataType is EMV, onlinePaymentCryptogram cannot be defined') unless
            values[:paymentData] && values[:paymentData][:onlinePaymentCryptogram].nil?
        end
      end

      rule(:paymentDataType, paymentData: :eciIndicator) do
        # type can only be 3DSecure if emvData is empty
        # old rule:
        # rule('when paymentDataType is EMV, eciIndicator': [:paymentDataType, [:paymentData, :eciIndicator]]) do |type, eci|
        #   type.eql?('EMV') > eci.none?
        # end
        if values[:paymentDataType].eql?('EMV')
          key.failure('when paymentDataType is EMV, eciIndicator cannot be defined') unless
            values[:paymentData] && values[:paymentData][:eciIndicator].nil?
        end
      end

      rule(:paymentDataType, paymentData: :emvData) do
        # type can only be 3DSecure if emvData is empty
        # old rule:
        # rule('when paymentDataType is EMV, emvData': [:paymentDataType, [:paymentData, :emvData]]) do |type, emv|
        #   type.eql?('EMV') > emv.filled?
        # end
        if values[:paymentDataType].eql?('EMV')
          key.failure('when paymentDataType is EMV, emvData must be filled') unless
            values[:paymentData] && values[:paymentData][:emvData]
        end
      end

      rule(:paymentDataType, paymentData: :encryptedPINData) do
        # type can only be 3DSecure if emvData is empty
        # old rule:
        # rule('when paymentDataType is EMV, encryptedPINData': [:paymentDataType, [:paymentData, :encryptedPINData]]) do |type, pin|
        #   type.eql?('EMV') > pin.filled?
        # end
        if values[:paymentDataType].eql?('EMV')
          key.failure('when paymentDataType is EMV, encryptedPINData must be filled') unless
            values[:paymentData] && values[:paymentData][:encryptedPINData]
        end
      end
    end

    TokenDataSchema = TokenDataContract.new

    class Error < StandardError; end

    module InstanceMethods
      attr_reader :output

      def validate
        @validation ||= @schema.call(@input)

        @output = @validation.to_h

        return true if @validation.success?

        raise Error, "validation error: #{@validation.errors.to_h.keys.join(', ')}"
      end

      def valid?
        validate
      rescue Error
        false
      end

      def errors
        valid? unless @validation

        @validation.errors.to_h.sort
      end

      def errors_formatted(node = [errors])
        node.pop.flat_map do |key, value|
          if value.is_a?(Array)
            value.map { |error| "#{(node + [key]).join('.')} #{error}" }
          else
            errors_formatted(node + [key, value])
          end
        end
      end
    end

    class Token
      include InstanceMethods
      class Error < ::Pedicel::Validator::Error; end
      def initialize(input)
        @input = input
        @schema = TokenSchema
      end
    end

    class TokenData
      include InstanceMethods
      class Error < ::Pedicel::Validator::Error; end
      def initialize(input)
        @input = input
        @schema = TokenDataSchema
      end
    end
  end
end
