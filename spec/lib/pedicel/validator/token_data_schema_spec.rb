require 'pedicel/validator'
require 'expectations/schema'
require 'lib/pedicel/validator/helper'

describe 'Pedicel::Validator::TokenDataSchema' do
  let(:tds) { Pedicel::Validator::TokenDataSchema }
  let(:token_data_h) { JSON.parse(token.unencrypted_data.to_hash.to_json, symbolize_names: true) }
  subject { token_data_h }

  context 'wrong data' do
    %i[
      applicationPrimaryAccountNumber
      applicationExpirationDate
      currencyCode
      transactionAmount
      deviceManufacturerIdentifier
      paymentDataType
      paymentData
    ].each do |required_key|
      it "errs when #{required_key} is missing" do
        token_data_h.delete(required_key)
        is_expected.to dissatisfy_schema(tds, required_key => ['is missing'])
      end
    end

    %i[
      applicationPrimaryAccountNumber
      applicationExpirationDate
      currencyCode
      cardholderName
      deviceManufacturerIdentifier
      paymentDataType
    ].each do |string_key|
      it "errs when #{string_key} is not a string" do
        token_data_h.merge!(string_key => 42)
        is_expected.to dissatisfy_schema(tds, string_key => ['must be a string'])
      end
    end

    it 'errs when applicationPrimaryAccountNumber is not a PAN' do
      %w[
        0123123412341234
        1234567890
        12345678901234567890
        1234A23412341234
      ].each do |invalid_value|
        token_data_h[:applicationPrimaryAccountNumber] = invalid_value
        is_expected.to dissatisfy_schema(tds, applicationPrimaryAccountNumber: ['must be a pan'])
      end
    end

    it 'errs when applicationExpirationDate is not a date' do
      %w[12345 1234567 1A3456].each do |invalid_value|
        token_data_h[:applicationExpirationDate] = invalid_value
        is_expected.to dissatisfy_schema(tds, applicationExpirationDate: ['must be formatted YYMMDD'])
      end
    end

    it 'errs when currencyCode is not a currency code' do
      %w[11 11A 1111].each do |invalid_value|
        token_data_h[:currencyCode] = invalid_value
        is_expected.to dissatisfy_schema(tds, currencyCode: ['must be an ISO 4217 numeric code'])
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
        token_data_h[:transactionAmount] = invalid_value
        is_expected.to dissatisfy_schema(tds, transactionAmount: ['must be an integer'])
      end
    end

    it 'errs when deviceManufacturerIdentifier is not hex' do
      %w[42-42 42Z].each do |invalid_value|
        token_data_h[:deviceManufacturerIdentifier] = invalid_value
        is_expected.to dissatisfy_schema(tds, deviceManufacturerIdentifier: ['must be hex'])
      end
    end

    it 'errs when paymentDataType is unsupported' do
      %w[3dsecure emv 3D Secure 3DSecure2 EMVCo].each do |invalid_value|
        token_data_h[:paymentDataType] = invalid_value
        is_expected.to dissatisfy_schema(tds, paymentDataType: ['must be one of: 3DSecure, EMV'])
      end
    end

    context 'paymentDataType is 3DSecure' do
      it 'can be happy' do
        is_expected.to satisfy_schema(tds)
      end

      it 'errs when onlinePaymentCryptogram is missing' do
        token_data_h[:paymentDataType] = '3DSecure'
        token_data_h[:paymentData].delete(:onlinePaymentCryptogram)
        is_expected.to dissatisfy_schema(tds, 'when paymentDataType is 3DSecure, onlinePaymentCryptogram': ['must be filled'])
      end

      it 'errs when emvData is present' do
        token_data_h[:paymentDataType] = '3DSecure'
        token_data_h[:paymentData][:emvData] = Base64.strict_encode64('EMV payment structure')
        is_expected.to dissatisfy_schema(tds, 'when paymentDataType is 3DSecure, emvData': ['cannot be defined'])
      end

      it 'errs when encryptedPINData is present' do
        token_data_h[:paymentDataType] = '3DSecure'
        token_data_h[:paymentData][:encryptedPINData] = 'a1b2c3d4e5f6'
        is_expected.to dissatisfy_schema(tds, 'when paymentDataType is 3DSecure, encryptedPINData': ['cannot be defined'])
      end
    end

    context 'paymentDataType is EMV' do
      let(:orig) { JSON.parse(token.unencrypted_data.to_hash.to_json, symbolize_names: true) }

      before(:each) do
        token_data_h[:paymentDataType] = 'EMV'
        token_data_h[:paymentData].delete(:onlinePaymentCryptogram)
        token_data_h[:paymentData].delete(:eciIndicator)
        token_data_h[:paymentData][:emvData] = Base64.strict_encode64('EMV payment structure')
        token_data_h[:paymentData][:encryptedPINData] = 'a1b2c3d4e5f6'
      end

      it 'can be happy' do
        is_expected.to satisfy_schema(tds)
      end

      it 'errs when onlinePaymentCryptogram is present' do
        token_data_h[:paymentData][:onlinePaymentCryptogram] = orig[:paymentData][:onlinePaymentCryptogram]
        is_expected.to dissatisfy_schema(tds, 'when paymentDataType is EMV, onlinePaymentCryptogram': ['cannot be defined'])
      end

      it 'errs when eciIndicator is present' do
        token_data_h[:paymentData][:eciIndicator] = orig[:paymentData][:eciIndicator]
        is_expected.to dissatisfy_schema(tds, 'when paymentDataType is EMV, eciIndicator': ['cannot be defined'])
      end

      it 'errs when emvData is missing' do
        token_data_h[:paymentData].delete(:emvData)
        is_expected.to dissatisfy_schema(tds, 'when paymentDataType is EMV, emvData': ['must be filled'])
      end

      it 'errs when encryptedPINData is missing' do
        token_data_h[:paymentData].delete(:encryptedPINData)
        is_expected.to dissatisfy_schema(tds, 'when paymentDataType is EMV, encryptedPINData': ['must be filled'])
      end
    end
  end
end
