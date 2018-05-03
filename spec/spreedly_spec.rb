require 'pedicel'
require 'json'

describe "Spreedly's gala Ruby library's test case" do
  let(:private_key) do
    <<~PEM
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIDqrpF0KEFW4Ncb76vyBi3StFLiT222sFC0wC3LsP1M9oAoGCCqGSM49
    AwEHoUQDQgAED44gNZExKHUk9sMuXeZEBazNA+agV/VJK8vFug/rwuzqmzKE5v7q
    UTNRkR3gNi2lU68AJ6RoaDtBE6mBdjbuFQ==
    -----END EC PRIVATE KEY-----
    PEM
  end

  let(:certificate) do
    <<~PEM
      -----BEGIN CERTIFICATE-----
      MIIEcDCCBBagAwIBAgIIUyrEM4IzBHQwCgYIKoZIzj0EAwIwgYAxNDAyBgNVBAMM
      K0FwcGxlIFdvcmxkd2lkZSBEZXZlbG9wZXIgUmVsYXRpb25zIENBIC0gRzIxJjAk
      BgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApB
      cHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0xNDEwMjYxMjEwMTBaFw0xNjExMjQx
      MjEwMTBaMIGhMS4wLAYKCZImiZPyLGQBAQwebWVyY2hhbnQuY29tLnNlYXRnZWVr
      LlNlYXRHZWVrMTQwMgYDVQQDDCtNZXJjaGFudCBJRDogbWVyY2hhbnQuY29tLnNl
      YXRnZWVrLlNlYXRHZWVrMRMwEQYDVQQLDAo5QjNRWTlXQlo1MRcwFQYDVQQKDA5T
      ZWF0R2VlaywgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMB
      BwNCAAQPjiA1kTEodST2wy5d5kQFrM0D5qBX9Ukry8W6D+vC7OqbMoTm/upRM1GR
      HeA2LaVTrwAnpGhoO0ETqYF2Nu4Vo4ICVTCCAlEwRwYIKwYBBQUHAQEEOzA5MDcG
      CCsGAQUFBzABhitodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDA0LWFwcGxld3dk
      cmNhMjAxMB0GA1UdDgQWBBQWGfKgPgVBX8JOv84q1c04HShMmzAMBgNVHRMBAf8E
      AjAAMB8GA1UdIwQYMBaAFIS2hMw6hmJyFlmU6BqjvUjfOt8LMIIBHQYDVR0gBIIB
      FDCCARAwggEMBgkqhkiG92NkBQEwgf4wgcMGCCsGAQUFBwICMIG2DIGzUmVsaWFu
      Y2Ugb24gdGhpcyBjZXJ0aWZpY2F0ZSBieSBhbnkgcGFydHkgYXNzdW1lcyBhY2Nl
      cHRhbmNlIG9mIHRoZSB0aGVuIGFwcGxpY2FibGUgc3RhbmRhcmQgdGVybXMgYW5k
      IGNvbmRpdGlvbnMgb2YgdXNlLCBjZXJ0aWZpY2F0ZSBwb2xpY3kgYW5kIGNlcnRp
      ZmljYXRpb24gcHJhY3RpY2Ugc3RhdGVtZW50cy4wNgYIKwYBBQUHAgEWKmh0dHA6
      Ly93d3cuYXBwbGUuY29tL2NlcnRpZmljYXRlYXV0aG9yaXR5LzA2BgNVHR8ELzAt
      MCugKaAnhiVodHRwOi8vY3JsLmFwcGxlLmNvbS9hcHBsZXd3ZHJjYTIuY3JsMA4G
      A1UdDwEB/wQEAwIDKDBPBgkqhkiG92NkBiAEQgxARjkzOEY0NjU4Q0EyQzFDOUMz
      OEI4REZDQjVEQkIyQTIyNDU2MDdEREUyRjExNDYyMEU4NDY4RUY1MkQyMDhDQTAK
      BggqhkjOPQQDAgNIADBFAiB+Q4zzpMj2DJTCIhDFBcmwK1zQAC70fY2IsYd8+Nxu
      uwIhAKj9RrTOyiaQnoT5Mqi3UHopb6xTugl3LUDBloraBHyP
      -----END CERTIFICATE-----
    PEM
  end

  let(:pedicel) do
    Pedicel::EC.new(JSON.parse(Base64.decode64(<<~B64
      ewogICJ2ZXJzaW9uIjoiRUNfdjEiLAogICJkYXRhIjoiNE9aaG8xNWU5WXA1SzBFdEtlcmdL
      emVScFBBam5LSHdtU05uYWd4aGp3aEtRNWQyOXNmVFhqZGJoMUN0VEo0RFlqc0Q2a2Z1bE5V
      blltQlRzcnVwaEJ6N1JSVkkxV0k4UDBMcm1mVG5JbWpjcTFtaStCUk43RXRSMnk2TWtEbUFy
      NzhhbmZmOTFobGMreDhlV0QvTnBPL29aMWV5NXFWNVJCeS9KcDV6aDZuZFZVVnE4TUhIaHZR
      djRwTHk1VGZpNTdZbzRSVWhBc3lYeVRoNHgvcDEzNjBCWm1vV29tSzE1TmNKZlVtb1VDdXdF
      WW9pN3hVa1J3TnIxejRNS256TWZuZVNScFVnZGMwd0FETWVCNnUxamN1d3FRbm5oMmN1c2lh
      Z09UQ2ZENmpPNnRtb3V2dTZLTzU0dVU3YkFiS3o2Y29jSU9FQU9jNmtleUZYRzVkZnc4aTNo
      Smc2RzJ2SWVmSEN3Y0t1MXpGQ0hyNFA3akxuWUZERWh2eExtMUtza0RjdVplUUhBa0JNbUxS
      U2dqOU5JY3BCYTk0Vk4vSlRnYThXNzVJV0FBPT0iLAogICJzaWduYXR1cmUiOiJNSUFHQ1Nx
      R1NJYjNEUUVIQXFDQU1JQUNBUUV4RHpBTkJnbGdoa2dCWlFNRUFnRUZBRENBQmdrcWhraUc5
      dzBCQndFQUFLQ0FNSUlENGpDQ0E0aWdBd0lCQWdJSUpFUHlxQWFkOVhjd0NnWUlLb1pJemow
      RUF3SXdlakV1TUN3R0ExVUVBd3dsUVhCd2JHVWdRWEJ3YkdsallYUnBiMjRnU1c1MFpXZHlZ
      WFJwYjI0Z1EwRWdMU0JITXpFbU1DUUdBMVVFQ3d3ZFFYQndiR1VnUTJWeWRHbG1hV05oZEds
      dmJpQkJkWFJvYjNKcGRIa3hFekFSQmdOVkJBb01Da0Z3Y0d4bElFbHVZeTR4Q3pBSkJnTlZC
      QVlUQWxWVE1CNFhEVEUwTURreU5USXlNRFl4TVZvWERURTVNRGt5TkRJeU1EWXhNVm93WHpF
      bE1DTUdBMVVFQXd3Y1pXTmpMWE50Y0MxaWNtOXJaWEl0YzJsbmJsOVZRelF0VUZKUFJERVVN
      QklHQTFVRUN3d0xhVTlUSUZONWMzUmxiWE14RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0
      eEN6QUpCZ05WQkFZVEFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUV3
      aFYzN2V2V3g3SWhqMmpkY0pDaElZM0hzTDF2TENnOWhHQ1YyVXIwcFVFYmcwSU8yQkh6UUg2
      RE14OGNWTVAzNnpJZzFyclYxTy8wa29tSlBud1BFNk9DQWhFd2dnSU5NRVVHQ0NzR0FRVUZC
      d0VCQkRrd056QTFCZ2dyQmdFRkJRY3dBWVlwYUhSMGNEb3ZMMjlqYzNBdVlYQndiR1V1WTI5
      dEwyOWpjM0F3TkMxaGNIQnNaV0ZwWTJFek1ERXdIUVlEVlIwT0JCWUVGSlJYMjIvVmRJR0dp
      WWwyTDM1WGhRZm5tMWdrTUF3R0ExVWRFd0VCL3dRQ01BQXdId1lEVlIwakJCZ3dGb0FVSS9K
      SnhFK1Q1TzhuNXNUMktHdy9vcnY5TGtzd2dnRWRCZ05WSFNBRWdnRVVNSUlCRURDQ0FRd0dD
      U3FHU0liM1kyUUZBVENCL2pDQnd3WUlLd1lCQlFVSEFnSXdnYllNZ2JOU1pXeHBZVzVqWlNC
      dmJpQjBhR2x6SUdObGNuUnBabWxqWVhSbElHSjVJR0Z1ZVNCd1lYSjBlU0JoYzNOMWJXVnpJ
      R0ZqWTJWd2RHRnVZMlVnYjJZZ2RHaGxJSFJvWlc0Z1lYQndiR2xqWVdKc1pTQnpkR0Z1WkdG
      eVpDQjBaWEp0Y3lCaGJtUWdZMjl1WkdsMGFXOXVjeUJ2WmlCMWMyVXNJR05sY25ScFptbGpZ
      WFJsSUhCdmJHbGplU0JoYm1RZ1kyVnlkR2xtYVdOaGRHbHZiaUJ3Y21GamRHbGpaU0J6ZEdG
      MFpXMWxiblJ6TGpBMkJnZ3JCZ0VGQlFjQ0FSWXFhSFIwY0RvdkwzZDNkeTVoY0hCc1pTNWpi
      MjB2WTJWeWRHbG1hV05oZEdWaGRYUm9iM0pwZEhrdk1EUUdBMVVkSHdRdE1Dc3dLYUFub0NX
      R0kyaDBkSEE2THk5amNtd3VZWEJ3YkdVdVkyOXRMMkZ3Y0d4bFlXbGpZVE11WTNKc01BNEdB
      MVVkRHdFQi93UUVBd0lIZ0RBUEJna3Foa2lHOTJOa0JoMEVBZ1VBTUFvR0NDcUdTTTQ5QkFN
      Q0EwZ0FNRVVDSUhLS253K1NveXE1bVhRcjFWNjJjMEJYS3BhSG9kWXU5VFdYRVBVV1BwYnBB
      aUVBa1RlY2ZXNitXNWwwcjBBRGZ6VENQcTJZdGJTMzl3MDFYSWF5cUJOeThiRXdnZ0x1TUlJ
      Q2RhQURBZ0VDQWdoSmJTKy9PcGphbHpBS0JnZ3Foa2pPUFFRREFqQm5NUnN3R1FZRFZRUURE
      QkpCY0hCc1pTQlNiMjkwSUVOQklDMGdSek14SmpBa0JnTlZCQXNNSFVGd2NHeGxJRU5sY25S
      cFptbGpZWFJwYjI0Z1FYVjBhRzl5YVhSNU1STXdFUVlEVlFRS0RBcEJjSEJzWlNCSmJtTXVN
      UXN3Q1FZRFZRUUdFd0pWVXpBZUZ3MHhOREExTURZeU16UTJNekJhRncweU9UQTFNRFl5TXpR
      Mk16QmFNSG94TGpBc0JnTlZCQU1NSlVGd2NHeGxJRUZ3Y0d4cFkyRjBhVzl1SUVsdWRHVm5j
      bUYwYVc5dUlFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhS
      cGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURW
      UVFHRXdKVlV6QlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJQQVhFWVFaMTJT
      RjFScGVKWUVIZHVpQW91L2VlNjVONEkzOFM1UGhNMWJWWmxzMXJpTFFsM1lOSWs1N3Vnajlk
      aGZPaU10MnUyWnd2c2pvS1lUL1ZFV2pnZmN3Z2ZRd1JnWUlLd1lCQlFVSEFRRUVPakE0TURZ
      R0NDc0dBUVVGQnpBQmhpcG9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQTBM
      V0Z3Y0d4bGNtOXZkR05oWnpNd0hRWURWUjBPQkJZRUZDUHlTY1JQaytUdkorYkU5aWhzUDZL
      Ny9TNUxNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdId1lEVlIwakJCZ3dGb0FVdTdEZW9WZ3pp
      SnFraXBuZXZyM3JyOXJMSktzd053WURWUjBmQkRBd0xqQXNvQ3FnS0lZbWFIUjBjRG92TDJO
      eWJDNWhjSEJzWlM1amIyMHZZWEJ3YkdWeWIyOTBZMkZuTXk1amNtd3dEZ1lEVlIwUEFRSC9C
      QVFEQWdFR01CQUdDaXFHU0liM1kyUUdBZzRFQWdVQU1Bb0dDQ3FHU000OUJBTUNBMmNBTUdR
      Q01EclBjb05SRnBteGh2czF3MWJLWXIvMEYrM1pEM1ZOb282KzhaeUJYa0szaWZpWTk1dFpu
      NWpWUVEyUG5lbkMvZ0l3TWkzVlJDR3dvd1YzYkYzek9EdVFaLzBYZkN3aGJaWlB4bkpwZ2hK
      dlZQaDZmUnVaeTVzSmlTRmhCcGtQQ1pJZEFBQXhnZ0ZmTUlJQld3SUJBVENCaGpCNk1TNHdM
      QVlEVlFRRERDVkJjSEJzWlNCQmNIQnNhV05oZEdsdmJpQkpiblJsWjNKaGRHbHZiaUJEUVNB
      dElFY3pNU1l3SkFZRFZRUUxEQjFCY0hCc1pTQkRaWEowYVdacFkyRjBhVzl1SUVGMWRHaHZj
      bWwwZVRFVE1CRUdBMVVFQ2d3S1FYQndiR1VnU1c1akxqRUxNQWtHQTFVRUJoTUNWVk1DQ0NS
      RDhxZ0duZlYzTUEwR0NXQ0dTQUZsQXdRQ0FRVUFvR2t3R0FZSktvWklodmNOQVFrRE1Rc0dD
      U3FHU0liM0RRRUhBVEFjQmdrcWhraUc5dzBCQ1FVeER4Y05NVFF4TURJM01UazFNVFF6V2pB
      dkJna3Foa2lHOXcwQkNRUXhJZ1FnZTAxZmU0ZTErd29SbmFWM284YlpMN3ZtVExFRHNuWmZU
      UXErRDdHWWpuSXdDZ1lJS29aSXpqMEVBd0lFUnpCRkFpRUE1MDkwZXlyVUU3cGpXYjhNcVVl
      RHAvdkVZOTh2dHJUMFV2cmUvNjZjY3FRQ0lDWWU2Y2VuNTE2eC94c2ZpL3RKcjNTYlRkeE8y
      NVpkTjFiUEgwSmlxZ3c3QUFBQUFBQUEiLAogICJoZWFkZXIiOnsKICAgICJ0cmFuc2FjdGlv
      bklkIjoiMjY4NmY1Mjk3ZjEyM2VjN2ZkOWQzMTA3NGQ0M2QyMDE5NTNjYTc1ZjA5ODg5MDM3
      NWYxM2FlZDI3MzdkOTJmMiIsCiAgICAiZXBoZW1lcmFsUHVibGljS2V5IjoiTUZrd0V3WUhL
      b1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFTXdsaW90ZjJJQ2ppTXdSRWRxeUhTaWxxWnp1
      VjJmWmV5ODZuQklEbFRZOHNOTUp2OUNQcEw1L0RLZzRiSUVNZTZxYWo2N216NExXZHI3RXIw
      TGQ1cUE9PSIsCiAgICAicHVibGljS2V5SGFzaCI6Ikxic1V3QVQ2dzFKVjl0RlhvY1U4MTNU
      Q0hrcytMU3VGRjBSL2VCa3JXblE9IgogIH0KfQo=
    B64
    )))
  end

  let(:decrypted_data) do
    {
      'applicationPrimaryAccountNumber' => Base64.decode64('NDEwOTM3MDI1MTAwNDMyMA=='),
      'applicationExpirationDate'       => '200731',
      'currencyCode'                    => '840',
      'transactionAmount'               => 100,
      'deviceManufacturerIdentifier'    => '040010030273',
      'paymentDataType'                 => '3DSecure',
      'paymentData'                     => {
        'onlinePaymentCryptogram' => 'Af9x/QwAA/DjmU65oyc1MAABAAA=',
        'eciIndicator'            => '5',
      },
    }.to_json
  end

  describe 'decryption with private key and certificate' do
    it 'decrypts correctly' do
      d = pedicel.decrypt(private_key: private_key, certificate: certificate, now: Time.new(2014,10,27,19,51,43))

      expect(d).to eq(decrypted_data)
    end
  end

  let(:symmetric_key) do
    ['1ce49a828f59d43861ba442fce6829b8218fbb0ab55b40206ac31058d66f5086'].pack('H*')
  end

  context 'symmetric key' do
    it 'finds the correct symmetric key' do
      skey = pedicel.symmetric_key(private_key: private_key, certificate: certificate)

      expect(skey).to eq(symmetric_key)
    end

    it 'can decrypt using the symmetric key' do
      expect(pedicel.decrypt(symmetric_key: symmetric_key, now: Time.new(2014,10,27,19,51,43))).to eq(decrypted_data)
    end
  end

  let (:shared_secret) do
    ['6b6a4f7de992740e7ad059f32d2bfccdf76559d1894e89c0a4e2ead737e0c7cc'].pack('H*')
  end

  context 'shared secret' do
    it 'finds the correct shared secret' do
      ss = pedicel.shared_secret(private_key: private_key)

      expect(ss).to eq(shared_secret)
    end
  end

  context 'deriving symmetric key from shared secret' do
    it 'works' do
      sk = pedicel.symmetric_key(shared_secret: shared_secret, certificate: certificate)

      expect(sk).to eq(symmetric_key)
    end
  end
end
