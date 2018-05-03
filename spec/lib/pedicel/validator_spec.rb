require 'pedicel/validator'
require 'pedicel-pay'

require 'json'
require 'digest'

describe Pedicel::Validator do
  let (:token) do
    backend = PedicelPay::Backend.generate
    client = backend.generate_client

    token = PedicelPay::Token.new.sample
    backend.encrypt_and_sign(token, recipient: client)

    token.to_hash
  end

  describe '.valid_token?' do
    it 'relies on validate_token' do
      expect(Pedicel::Validator).to receive(:validate_token).with(nil).and_return(true)

      expect(Pedicel::Validator.valid_token?(nil)).to eq(true)
    end

    it 'relies on validate_token' do
      expect(Pedicel::Validator).to receive(:validate_token).with(nil).and_raise(Pedicel::Validator::Error, 'boom')

      expect(Pedicel::Validator.valid_token?(nil)).to eq(false)
    end
  end

  describe '.validate_token' do
    subject { lambda { Pedicel::Validator.validate_token(token) } }

    it 'does not err on a valid token' do
      is_expected.to_not raise_error
    end

    it 'is truthy a valid token' do
      expect(Pedicel::Validator.validate_token(token)).to be_truthy
    end

    it 'errs when data is missing' do
      token.delete('data')
      is_expected.to raise_error(Pedicel::Validator::TokenFormatError, /data:/)
    end

    it 'errs when data is missing' do
      token.delete('data')
      is_expected.to raise_error(Pedicel::Validator::TokenFormatError, /data:/)
    end

    it 'errs when data is not a string' do
      token['data'] = [1,2,3]
      is_expected.to raise_error(Pedicel::Validator::TokenFormatError, /data:.*string/)

      token['data'] = { :'a string as a hash key' => 'a string in a hash value' }
      is_expected.to raise_error(Pedicel::Validator::TokenFormatError, /data:.*string/)
    end

    it 'errs when data is not Base 64' do
      token['data'] = '%'
      is_expected.to raise_error(Pedicel::Validator::TokenFormatError, /data:.*base.*64/)
    end
  end
end

describe Pedicel::Validator::Predicates do
  describe '.base64?' do
    def base64?(x); subject.base64?(x); end

    it 'true for valid base 64' do
      expect(base64?('')).to eq(true)
      expect(base64?('validbase64=')).to eq(true)
    end

    it 'false for invalid base 64' do
      expect(base64?(nil)).to be false
      expect(base64?('%')).to be false
      expect(base64?('fooo=')).to be false
      expect(base64?('f===')).to be false
    end
  end

  describe '.hex?' do
    def hex?(x); subject.hex?(x); end

    it 'true for a hex string' do
      expect(hex?('')).to be true
      expect(hex?(['a'..'f', 'A'..'F', 0..9].map(&:to_a).inject(&:concat).join)).to be true
    end

    it 'false for non-Hex characters' do
      expect(hex?('g')).to be false
      expect(hex?('G')).to be false
      expect(hex?('_')).to be false
      expect(hex?(' ')).to be false
      expect(hex?('/')).to be false
    end
  end

  describe '.pan?' do
    def pan?(x); subject.pan?(x); end

    it 'true for valid PANs' do
      expect(pan?('123456789012')).to be true
      expect(pan?('1234567890123456789')).to be true
      expect(pan?('1234567890123456')).to be true
      expect(pan?('1000000000000000')).to be true
    end

    it 'false if PAN contains anything but digits' do
      expect(pan?('1a34567890123456')).to be false
      expect(pan?('1 34567890123456')).to be false
      expect(pan?('1_34567890123456')).to be false
      expect(pan?('134567890123456 ')).to be false
      expect(pan?(' 134567890123456')).to be false
    end

    it 'false if PAN starts with a zero' do
      expect(pan?('0234567890123456')).to be false
    end

    it 'false if PAN is shorter than 12 digits' do
      expect(pan?('12345678901')).to be false
    end

    it 'false if PAN is longer than 19 digits' do
      expect(pan?('12345678901234567890')).to be false
    end
  end

  describe '.eci?' do
    def eci?(value)
      subject.eci?(value)
    end

    it 'is true for valid ECIs' do
      expect(eci?('05')).to be true
      expect(eci?('06')).to be true
      expect(eci?('07')).to be true
    end

    it 'is false for ECIs of wrong length' do
      expect(eci?('005')).to be false
      expect(eci?('5')).to   be false
      expect(eci?(' 05')).to be false
    end

    it 'is false for non-numeric ECIs' do
      expect(eci?('  ')).to be false
      expect(eci?('ab')).to be false
      expect(eci?('__')).to be false
    end
  end
end
