require 'pedicel/validator'
require 'expectations/schema'
require 'lib/pedicel/validator/helper'

describe 'Pedicel::Validator::TokenDataSchema' do
  let(:tds) { Pedicel::Validator::TokenDataSchema }
  let(:token_data_h) { JSON.parse(token.unencrypted_data.to_hash.to_json) }
  subject { token_data_h }

  context 'wrong data' do
    %w(
      applicationPrimaryAccountNumber
      applicationExpirationDate
      currencyCode
      transactionAmount
      deviceManufacturerIdentifier
      paymentDataType
      paymentData
    ).each do |required_key|
      it "errs when #{required_key} is missing" do
        token_data_h.delete(required_key)
        is_expected.to dissatisfy_schema(tds, required_key => ['is missing'])
      end
    end

    %w(
      applicationPrimaryAccountNumber
      applicationExpirationDate
      currencyCode
      cardholderName
      deviceManufacturerIdentifier
      paymentDataType
    ).each do |string_key|
      it "errs when #{string_key} is not a string" do
        token_data_h.merge!(string_key => 42)
        is_expected.to dissatisfy_schema(tds, string_key => ['must be a string'])
      end
    end

    it 'errs when applicationPrimaryAccountNumber is not a PAN' do
      %w(
        0123123412341234
        1234567890
        12345678901234567890
        1234A23412341234
      ).each do |invalid_value|
        token_data_h['applicationPrimaryAccountNumber'] = invalid_value
        is_expected.to dissatisfy_schema(tds, 'applicationPrimaryAccountNumber' => ['must be a pan'])
      end
    end

    it 'errs when applicationExpirationDate is not a date' do
      %w(12345 1234567 1A3456).each do |invalid_value|
        token_data_h['applicationExpirationDate'] = invalid_value
        is_expected.to dissatisfy_schema(tds, 'applicationExpirationDate' => ['must be formatted YYMMDD'])
      end
    end

    it 'errs when currencyCode is not a currency code' do
      %w(11 11A 1111).each do |invalid_value|
        token_data_h['currencyCode'] = invalid_value
        is_expected.to dissatisfy_schema(tds, 'currencyCode' => ['must be an ISO 4217 numeric code'])
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
        token_data_h['transactionAmount'] = invalid_value
        is_expected.to dissatisfy_schema(tds, 'transactionAmount' => ['must be an integer'])
      end
    end

    it 'errs when deviceManufacturerIdentifier is not hex' do
      %w(42-42 42Z).each do |invalid_value|
        token_data_h['deviceManufacturerIdentifier'] = invalid_value
        is_expected.to dissatisfy_schema(tds, 'deviceManufacturerIdentifier' => ['must be hex'])
      end
    end

    it 'errs when paymentDataType is unsupported' do
      %w(3dsecure emv 3D Secure 3DSecure2 EMVCo).each do |invalid_value|
        token_data_h['paymentDataType'] = invalid_value
        is_expected.to dissatisfy_schema(tds, 'paymentDataType' => ['must be one of: 3DSecure, EMV'])
      end
    end

    it 'errs when paymentDataType is 3DSecure but onlinePaymentCryptogram is missing'
  end
end
