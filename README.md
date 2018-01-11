# Pedicel

The stilk of an apple is also called a pedicel.

This Ruby gem will help you handle an Apple Pay `PKPaymentToken`.


## Toying around

Generate a private key:

    openssl ecparam -out private.key -name prime256v1 -genkey

Generate a CSR (Certificate Signing Request):

    openssl req -new -sha256 -key private.key -nodes -out newreq.pem -subj '/CN=foobar'

Now, if this was real, this CSR should be uploaded to the Apple developer
portal. But. For toying around ...

### Be your own CA (Certificate Authority)

What will happen:

a. We will have a certificate to use in place of the Apple Root CA G3
   Certificate.

b. Sign the CSR from above and thereby get a certificate.

#### Setup your CA

    docker run --rm -it -v $PWD:/from-host debian:stretch bash
    apt-get update && apt-get install -y openssl
    cd /from-host

First time:

    /usr/lib/ssl/misc/CA.pl -newca
    [enter]
    # Type "asdf" and [enter] for all the remaining questions (including
    # passphrase) for convenience.

This generated the dir `demoCA`.

Signing:

    /usr/lib/ssl/misc/CA.pl -sign # Grabs newreq.pem.
    Sign the certificate? [y/n]:y
    1 out of 1 certificate requests certified, commit? [y/n]y

This produced `newcert.pem`

### Using the good stuff

Grab `demoCA/cacert.pem`, or rather the certificate part of it and use it:

```ruby
Pedicel.config = Pedicel.config.merge(apple_root_ca_g3_cert_pem: '
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----'
)
```
