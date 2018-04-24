require 'pedicel/base'
require 'pedicel-pay'

describe 'Pedicel::Base' do
  let (:version)          { 'EC_v1' }
  let (:encrypted_data)   { 'this is encrypted' }
  let (:signature)        { 'this is the signature' }
  let (:transaction_id)   { 'transaction id' }
  let (:application_data) { 'application data' }

  let (:token_hash) do
    {
      'version'        => version,
      'data'           => Base64.encode64(encrypted_data),
      'signature'      => Base64.encode64(signature),
      'header' => {
        'transactionId' => transaction_id.unpack('H*').first,
      },
      'applicationData' => application_data.unpack('H*').first,
    }
  end

  let (:pedicel) { Pedicel::Base.new(token_hash) }

  describe 'basic accessors' do
    it '#version extracts the version as a symbol' do
      expect(pedicel.version).to eq(version.to_sym)
    end

    it '#encrypted_data extracts the raw encrypted data' do
      expect(pedicel.encrypted_data).to eq(encrypted_data)
    end

    it '#signature extracts the raw signature' do
      expect(pedicel.signature).to eq(signature)
    end

    it '#transaction_id extracts the raw transactionId' do
      expect(pedicel.transaction_id).to eq(transaction_id)
    end

    it '#application_data extracts the raw applicationData' do
      expect(pedicel.application_data).to eq(application_data)
    end

    it "#private_key_class returns the private key's class" do
      expect(pedicel.private_key_class).to eq(OpenSSL::PKey::EC)
    end

    it "#symmetric_algorithm returns the identifier for the symmetric encryption algorithm to be used" do
      expect(pedicel.symmetric_algorithm).to eq('aes-256-gcm')
    end
  end

  describe '#decrypt_aes' do
    let (:unencrypted_data) { 'unencrypted data' }
    let (:key) { OpenSSL::Digest::SHA256.new.update('key').digest }

    it 'decrypts with the correct key' do
      token_hash.merge!('data' => Base64.encode64(PedicelPay::Helper.encrypt(data: unencrypted_data, key: key)))

      expect(Pedicel::Base.new(token_hash).decrypt_aes(key: key)).to eq(unencrypted_data)
    end

    it 'errs when the wrong key is given' do
      wrong_key   = OpenSSL::Digest::SHA256.new.update('wrong key').digest

      token_hash.merge!('data' => Base64.encode64(PedicelPay::Helper.encrypt(data: unencrypted_data, key: key)))

      expect(Pedicel::Base.new(token_hash).decrypt_aes(key: key)).to eq(unencrypted_data)
      expect{Pedicel::Base.new(token_hash).decrypt_aes(key: wrong_key)}.to raise_error(Pedicel::AesKeyError)
    end

    it 'errs when an invalid key is given' do
      invalid_key = 'invalid key' # Invalid length; should be 32 bytes.

      expect{Pedicel::Base.new(token_hash).decrypt_aes(key: invalid_key)}.to raise_error(Pedicel::AesKeyError)
    end
  end

  describe '#valid_signature?' do
    it 'is correct'
  end

  describe '#signing_time_ok?' do
    it 'is correct'
  end

  describe '.verify_signature_certificate_oids' do
    it 'is correct'
  end

  describe '.verify_root_certificate' do
    it 'is correct'
  end

  describe '.verify_x509_chain' do
    it 'is correct'
  end

  describe '.verify_signed_time' do
    it 'is correct'
  end
end
