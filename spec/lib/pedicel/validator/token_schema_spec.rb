require 'pedicel/validator'
require 'expectations/schema'
require 'lib/pedicel/validator/helper'

describe 'Pedicel::Validator::TokenSchema' do
  let(:ts) { Pedicel::Validator::TokenSchema }

  it 'is happy about a hash with string keys' do
    expect(JSON.parse(token.to_json, symbolize_names: false)).to satisfy_schema(ts)
  end

  it 'is happy about a hash with symbolic keys' do
    expect(JSON.parse(token.to_json, symbolize_names: true)).to satisfy_schema(ts)
  end

  let(:token_h) { token.to_hash }
  subject { token_h }

  context 'wrong data' do
    it 'errs when data is missing' do
      token_h.delete(:data)
      is_expected.to dissatisfy_schema(ts, data: ['is missing'])
    end

    it 'errs when data is not a string' do
      token_h[:data] = [1,2,3]
      is_expected.to dissatisfy_schema(ts, data: ['must be a string'])

      token_h[:data] = { :'a string as a hash key' => 'a string in a hash value' }
      is_expected.to dissatisfy_schema(ts, data: ['must be a string'])
    end

    it 'errs when data is not Base64' do
      token_h[:data] = '%'
      is_expected.to dissatisfy_schema(ts, data: ['must be Base64'])
    end
  end

  context 'signature' do
    it 'errs when invalid' do
      token_h[:signature] = 'invalid signature'
      is_expected.to dissatisfy_schema(ts, signature: nil)
    end

    it 'errs when missing' do
      token_h.delete(:signature)
      is_expected.to dissatisfy_schema(ts, signature: ['is missing'])
    end

    it 'errs when not a string' do
      token_h[:signature] = 123
      is_expected.to dissatisfy_schema(ts, signature: ['must be a string'])
    end

    it 'errs when not a Base64 string' do
      token_h[:signature] = 'not Base64'
      is_expected.to dissatisfy_schema(ts, signature: ['must be Base64'])
    end
  end

  context 'version' do
    it 'errs when invalid' do
      token_h[:version] = 'invalid version'
      is_expected.to dissatisfy_schema(ts, version: nil)
    end

    it 'errs when missing' do
      token_h.delete(:version)
      is_expected.to dissatisfy_schema(ts, version: ['is missing'])
    end

    it 'errs when not a string' do
      token_h[:version] = 123
      is_expected.to dissatisfy_schema(ts, version: ['must be a string'])
    end

    it 'errs when not a supported version' do
      token_h[:version] = 'EC_v0'
      is_expected.to dissatisfy_schema(ts, version: ['must be one of: EC_v1, RSA_v1'])
    end
  end

  context 'header' do
    it 'errs when missing' do
      token_h.delete(:header)
      is_expected.to dissatisfy_schema(ts, header: ['is missing'])
    end

    it 'errs when not a hash' do
      ['asdf', [], 123].each do |invalid|
        token_h[:header] = invalid
        is_expected.to dissatisfy_schema(ts, header: ['must be a hash'])
      end
    end
  end

  context 'multiple errors' do
    it 'errs when data is missing and signature is wrong' do
      token_h.delete(:data)
      token_h[:signature] = 'invalid signature'
      is_expected.to dissatisfy_schema(ts, data: ['is missing'], signature: ['must be Base64'])
    end
  end
end
