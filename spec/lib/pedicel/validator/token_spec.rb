require 'pedicel/validator'
require 'lib/pedicel/validator/helper'

describe Pedicel::Validator::Token do
  let(:validator) { Pedicel::Validator::Token.new(token.to_hash) }

  describe '#valid?' do
    it 'relies on #validate' do
      return_value = 'return_value'
      expect(validator).to receive(:validate).and_return(return_value)
      expect(validator.valid?).to equal return_value
    end
  end

  describe '#validate' do
    context 'can be happy' do
      it 'does not err on a valid token' do
        expect{validator.validate}.to_not raise_error
      end

      it 'is truthy for a valid token' do
        expect(validator.validate).to be_truthy
      end
    end
  end
end
