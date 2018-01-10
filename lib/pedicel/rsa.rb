require 'base'

module Pedicel
  class RSA < Base

    private

    def symmetric_key(private_key)
      # RSA/ECB/OAEPWithSHA256AndMGF1Padding

      # OpenSSL::PKey::RSA#private_decrypt will use SHA1. Only. :-(

    end
  end
end
