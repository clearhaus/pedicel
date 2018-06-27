require 'pedicel/validator'
require 'expectations/schema'
require 'lib/pedicel/validator/helper'

describe 'Pedicel::Validator::TokenDataPaymentDataSchema' do
  let(:tdpds) { Pedicel::Validator::TokenDataPaymentDataSchema }
  let(:token_data_payment_data_h) { JSON.parse(token.unencrypted_data.to_hash.to_json, symbolize_names: true)[:paymentData] }
  subject { token_data_payment_data_h }

  %i[
    onlinePaymentCryptogram
    eciIndicator
    emvData
    encryptedPINData
  ].each do |payment_data_string_key|
    it "errs when #{payment_data_string_key} is not a string" do
      token_data_payment_data_h[payment_data_string_key] = 42

      is_expected.to dissatisfy_schema(tdpds, payment_data_string_key => ['must be a string'])
    end
  end

  context 'onlinePaymentCryptogram' do
    it 'may be present' do
      token_data_payment_data_h[:onlinePaymentCryptogram] = 'validBase64='
      is_expected.to satisfy_schema(tdpds)
    end

    it 'may be absent' do
      token_data_payment_data_h.delete(:onlinePaymentCryptogram)
      is_expected.to satisfy_schema(tdpds)
    end

    it 'errs when not Base64' do
      %w[% fooo= f===].each do |invalid_value|
        token_data_payment_data_h[:onlinePaymentCryptogram] = invalid_value

        is_expected.to dissatisfy_schema(tdpds, onlinePaymentCryptogram: ['must be Base64'])
      end
    end
  end

  context 'eciIndicator' do
    it 'may be present' do
      token_data_payment_data_h['eciIndicator'] = '05' # Valid ECI.
      is_expected.to satisfy_schema(tdpds)
    end

    it 'may be absent' do
      token_data_payment_data_h.delete('eciIndicator')
      is_expected.to satisfy_schema(tdpds)
    end

    it 'errs when invalid' do
      %w[1 123 1A].each do |invalid_value|
        token_data_payment_data_h[:eciIndicator] = invalid_value

        is_expected.to dissatisfy_schema(tdpds, eciIndicator: ['must be an ECI'])
      end
    end
  end

  context 'emvData' do
    it 'may be present' do
      token_data_payment_data_h['emvData'] = 'validBase64='
      is_expected.to satisfy_schema(tdpds)
    end

    it 'may be absent' do
      token_data_payment_data_h.delete('emvData')
      is_expected.to satisfy_schema(tdpds)
    end

    it 'errs when not Base64' do
      %w[% fooo= f===].each do |invalid_value|
        token_data_payment_data_h[:emvData] = invalid_value

        is_expected.to dissatisfy_schema(tdpds, emvData: ['must be Base64'])
      end
    end
  end

  context 'encryptedPINData' do
    it 'may be present' do
      token_data_payment_data_h[:encryptedPINData] = 'a1b2c3d4e5f6'
      is_expected.to satisfy_schema(tdpds)
    end

    it 'may be absent' do
      token_data_payment_data_h.delete(:encryptedPINData)
      is_expected.to satisfy_schema(tdpds)
    end

    it 'errs when not hex' do
      %w[42-42 42Z].each do |invalid_value|
        token_data_payment_data_h[:encryptedPINData] = invalid_value
        is_expected.to dissatisfy_schema(tdpds, encryptedPINData: ['must be hex'])
      end
    end
  end
end
