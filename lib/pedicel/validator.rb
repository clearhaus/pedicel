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

    module Predicates
      include Dry::Logic::Predicates
      # We should figure out how strict we should be. Hopefully we can discard
      # the above Base64? predicate and use the following simpler one:
      #predicate(:strict_base64?) { |x| !!Base64.strict_decode64(x) rescue false }

      predicate(:pan?) { |x| str?(x) && match_b.(x, /\A[1-9][0-9]{11,18}\z/) }

      predicate(:yymmdd?) { |x| str?(x) && match_b.(x, /\A\d{6}\z/) }

      predicate(:eci?) { |x| str?(x) && match_b.(x, /\A\d{1,2}\z/) }

      predicate(:ec_public_key?) { |x| base64?(x) && OpenSSL::PKey::EC.new(Base64.decode64(x)).check_key rescue false }

      predicate(:pkcs7_signature?) { |x| base64?(x) && !!OpenSSL::PKCS7.new(Base64.decode64(x)) rescue false }

      predicate(:iso4217_numeric?) { |x| match_b.(x, /\A[0-9]{3}\z/) }
    end

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

    class TokenSchemaKlass < Dry::Validation::Contract
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

    TokenSchema = TokenSchemaKlass.new
    class TokenDataPaymentDataSchemaKlass < Dry::Validation::Contract
      json do
        optional(:onlinePaymentCryptogram).filled(:str?)
        optional(:eciIndicator).filled(:str?, :eci?)

        optional(:emvData).filled(:str?)
        optional(:encryptedPINData).filled(:str?)
      end
      rule(:onlinePaymentCryptogram).validate(:is_base64)
      rule(:eciIndicator).validate(:is_eci)

      rule(:emvData).validate(:is_base64)
      rule(:encryptedPINData).validate(:is_hex)
    end
    TokenDataPaymentDataSchema = TokenDataPaymentDataSchemaKlass.new

    # TokenDataSchema = Dry::Validation.Schema(BaseSchema) do
    #   required(:applicationPrimaryAccountNumber).filled(:str?, :pan?)

    #   required(:applicationExpirationDate).filled(:str?, :yymmdd?)

    #   required(:currencyCode).filled(:str?, :iso4217_numeric?)

    #   required(:transactionAmount).filled(:int?)

    #   optional(:cardholderName).filled(:str?)

    #   required(:deviceManufacturerIdentifier).filled(:str?, :hex?)

    #   required(:paymentDataType).filled(:str?, included_in?: %w[3DSecure EMV])

    #   required(:paymentData).schema(TokenDataPaymentDataSchema)

    #   rule('when paymentDataType is 3DSecure, onlinePaymentCryptogram': [:paymentDataType, [:paymentData, :onlinePaymentCryptogram]]) do |type, cryptogram|
    #     type.eql?('3DSecure') > cryptogram.filled?
    #   end
    #   rule('when paymentDataType is 3DSecure, emvData': [:paymentDataType, [:paymentData, :emvData]]) do |type, emv|
    #     type.eql?('3DSecure') > emv.none?
    #   end
    #   rule('when paymentDataType is 3DSecure, encryptedPINData': [:paymentDataType, [:paymentData, :encryptedPINData]]) do |type, pin|
    #     type.eql?('3DSecure') > pin.none?
    #   end

    #   rule('when paymentDataType is EMV, onlinePaymentCryptogram': [:paymentDataType, [:paymentData, :onlinePaymentCryptogram]]) do |type, cryptogram|
    #     type.eql?('EMV') > cryptogram.none?
    #   end
    #   rule('when paymentDataType is EMV, eciIndicator': [:paymentDataType, [:paymentData, :eciIndicator]]) do |type, eci|
    #     type.eql?('EMV') > eci.none?
    #   end
    #   rule('when paymentDataType is EMV, emvData': [:paymentDataType, [:paymentData, :emvData]]) do |type, emv|
    #     type.eql?('EMV') > emv.filled?
    #   end
    #   rule('when paymentDataType is EMV, encryptedPINData': [:paymentDataType, [:paymentData, :encryptedPINData]]) do |type, pin|
    #     type.eql?('EMV') > pin.filled?
    #   end

    # end

    class Error < StandardError; end

    module InstanceMethods
      attr_reader :output

      def validate
        @validation ||= @schema.call(@input)

        @output = @validation.output

        return true if @validation.success?

        raise Error, "validation error: #{@validation.errors.keys.join(', ')}"
      end

      def valid?
        validate
      rescue Error
        false
      end

      def errors
        valid? unless @validation

        @validation.errors
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
