require 'pedicel/validator'
require 'lib/pedicel/validator/helper'

describe Pedicel::Validator::TokenData do
  let(:token_data_h) { JSON.parse(token.unencrypted_data.to_hash.to_json) }
  let(:validator) { Pedicel::Validator::TokenData.new(token_data_h.to_hash) }

  describe '#valid?' do
    it 'relies on #validate' do
      return_value = 'return_value'
      expect(validator).to receive(:validate).and_return(return_value)
      expect(validator.valid?).to equal return_value
    end
  end

  describe '#validate' do
    context 'can be happy' do
      subject { lambda { validator.validate } }

      it 'does not err on a valid token' do
        is_expected.to_not raise_error
      end

      it 'is truthy for a valid token' do
        expect(validator.validate).to be_truthy
      end
    end
  end
end
