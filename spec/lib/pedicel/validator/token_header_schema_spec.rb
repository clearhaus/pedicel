require 'pedicel/validator'
require 'expectations/schema'
require 'lib/pedicel/validator/helper'

valid_ec_public_key = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0wzW/i0nT3XOeo6srobJRGnUlmqGTFahuHEOw4M9nxUlTBaQUNc8HlN/z1HbepGXTZWDSJB2deCGfhsrOdVryQ=='

describe 'Pedicel::Validator::TokenHeaderSchema' do
  let(:ths) { Pedicel::Validator::TokenHeaderSchema }
  let(:header_h) { token.to_hash[:header] }
  subject { header_h }

  context 'applicationData' do
    it 'may be present' do
      is_expected.to satisfy_schema(ths)
    end

    it 'may be missing' do
      header_h.delete('applicationData')
      is_expected.to satisfy_schema(ths)
    end

    it 'errs when null' do
      header_h[:applicationData] = nil
      is_expected.to dissatisfy_schema(ths, applicationData: ['must be filled'])
    end

    it 'errs when not a string' do
      header_h[:applicationData] = 123
      is_expected.to dissatisfy_schema(ths, applicationData: ['must be a string'])
    end

    it 'errs when not a hex string' do
      header_h[:applicationData] = 'not hex'
      is_expected.to dissatisfy_schema(ths, applicationData: ['must be hex'])
    end
  end

  context 'ephemeralPublicKey' do
    it 'errs when invalid' do
      header_h[:ephemeralPublicKey] = 'invalid ephemeralPublicKey'
      is_expected.to dissatisfy_schema(ths, ephemeralPublicKey: ['must be Base64'])
    end
    it 'errs when not a string' do
      header_h[:ephemeralPublicKey] = 123
      is_expected.to dissatisfy_schema(ths, ephemeralPublicKey: ['must be a string'])
    end

    it 'errs when not Base64' do
      header_h[:ephemeralPublicKey] = '%'
      is_expected.to dissatisfy_schema(ths, ephemeralPublicKey: ['must be Base64'])
    end

    it 'errs when invalid EC public key' do
      header_h[:ephemeralPublicKey] = 'validBase64ButInvalidEcPublicKey'
      is_expected.to dissatisfy_schema(ths, ephemeralPublicKey: ['must be an EC public key'])
    end
  end

  context 'wrappedKey' do
    it 'errs when not a string' do
      header_h[:wrappedKey] = 123
      is_expected.to dissatisfy_schema(ths, wrappedKey: ['must be a string'])
    end

    it 'errs when not Base64' do
      header_h[:wrappedKey] = 'invalid wrappedKey'
      is_expected.to dissatisfy_schema(ths, wrappedKey: ['must be Base64'])
    end
  end

  context 'consistency among ephemeralPublicKey and wrappedKey' do
    it 'errs when both are present' do
      header_h[:ephemeralPublicKey] = valid_ec_public_key
      header_h[:wrappedKey] = 'validBase64='
      is_expected.to dissatisfy_schema(ths, 'ephemeralPublicKey xor wrappedKey': ['must be filled'])
    end

    it 'errs when neither are present' do
      header_h.delete(:ephemeralPublicKey)
      header_h.delete(:wrappedKey)
      is_expected.to dissatisfy_schema(ths, 'ephemeralPublicKey xor wrappedKey': ['must be filled'])
    end

    it 'does not err when only ephemeralPublicKey is present' do
      header_h[:ephemeralPublicKey] = valid_ec_public_key
      header_h.delete(:wrappedKey)
      is_expected.to satisfy_schema(ths)
    end

    it 'does not err when only wrappedKey is present' do
      header_h.delete(:ephemeralPublicKey)
      header_h[:wrappedKey] = 'validBase64='
      is_expected.to satisfy_schema(ths)
    end
  end

  context 'publicKeyHash' do
    it 'must be present' do
      header_h.delete(:publicKeyHash)
      is_expected.to dissatisfy_schema(ths, publicKeyHash: ['is missing'])
    end

    it 'errs when not a string' do
      header_h[:publicKeyHash] = 123
      is_expected.to dissatisfy_schema(ths, publicKeyHash: ['must be a string'])
    end

    it 'errs when not Base64' do
      header_h[:publicKeyHash] = '%'
      is_expected.to dissatisfy_schema(ths, publicKeyHash: ['must be Base64'])
    end

    it 'errs when invalid' do
      header_h[:publicKeyHash] = 'validBase64ButInvalidEcPublicKeyHash'
      is_expected.to dissatisfy_schema(ths, publicKeyHash: ['must be a Base64-encoded SHA-256'])
    end
  end

  context 'transactionId' do
    it 'errs when missing' do
      header_h.delete(:transactionId)
      is_expected.to dissatisfy_schema(ths, transactionId: ['is missing'])
    end

    it 'errs when not a string' do
      header_h[:transactionId] = 123
      is_expected.to dissatisfy_schema(ths, transactionId: ['must be a string'])
    end

    it 'errs when not a hex string' do
      header_h[:transactionId] = 'not hex'
      is_expected.to dissatisfy_schema(ths, transactionId: ['must be hex'])
    end
  end
end
