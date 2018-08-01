require 'pedicel/validator'

describe 'Pedicel::Validator' do
  let(:valid_data) do
    {
      applicationPrimaryAccountNumber: '123456789012',
      applicationExpirationDate:       '200101',
      currencyCode:                    '208',
      transactionAmount:               1234,
      deviceManufacturerIdentifier:    '0',
      paymentDataType:                 '3DSecure',
      paymentData:                     { onlinePaymentCryptogram: 'NDI=' }
    }
  end

  def validator(data)
    Pedicel::Validator::TokenData.new(data)
  end

  it 'finds no errors in the valid data' do
    expect(validator(valid_data).valid?).to be true
  end

  it 'formats a bunch of errors as expected' do
    invalid_data = valid_data.merge(currencyCode: '34')
    invalid_data[:deviceManufacturerIdentifier] = 'g'
    invalid_data[:paymentData][:eciIndicator] = ''

    expect(validator(invalid_data).errors_formatted).to eq [
      'currencyCode must be an ISO 4217 numeric code',
      'deviceManufacturerIdentifier must be hex',
      'paymentData.eciIndicator must be filled'
    ]
  end

  it 'formats custom errors as expected' do
    invalid_data = valid_data.merge(transactionAmount: '1234')
    invalid_data[:paymentData].delete(:onlinePaymentCryptogram)

    expect(validator(invalid_data).errors_formatted).to eq [
      'transactionAmount must be an integer',
      'when paymentDataType is 3DSecure, onlinePaymentCryptogram must be filled'
    ]
  end
end
