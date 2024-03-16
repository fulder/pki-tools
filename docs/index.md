# PKI Tools

PKI tools exposes a high level `cryptography` API and wrappers for e.g.:

* Loading certificates from PEM strings/files/cryptography object into
  a [pydantic][pydantic-docs] model including all
  [x509 v3 extensions][ext-draft]
* Checking revocation of certificates using [OCSP][ocsp-draft] with
  [CRL][crl-draft] fallback
* Creating Certs, CSR, CRL easy with pure pydantic objects to e.g. get a
  PEM file

## Install

`pip install pki-tools`

## Log level

`pki-tools` use [loguru] library for logging. Where the default log level
is `DEBUG`, if you want to change it you could e.g. use the `LOGURU_LEVEL`
environment variable.

## Features

* [Checking Revocation][checking-revocation] - checking
  revocation status of certificates using OCSP and/or CRL

### Creating objects

* [Create Self Signed Certificate][pki_tools.types.certificate.Certificate--create-self-signed-certificate]
* [Create CSR][pki_tools.types.csr.CertificateSigningRequest--example]

### Loading x509 objects

| Function          | [Certificate][pki_tools.types.certificate.Certificate]                                                                             | CSR | [Chain][pki_tools.types.chain.Chain]                                            |
|-------------------|---------------------------------------------------------------------------------------------|-----|---------------------------------------------------------------------------------|
| From PEM String   | [from_pem_string][pki_tools.types.certificate.Certificate--initcryptoparserfrom_pem_string] |     | [from_pem_string][pki_tools.types.chain.Chain--initcryptoparserfrom_pem_string] |
| From file         | [from_file][pki_tools.types.certificate.Certificate--initcryptoparserfrom_file]             |     | [from_file][pki_tools.types.chain.Chain--initcryptoparserfrom_file]             |
| From cryptography | [from_cryptography][pki_tools.types.certificate.Certificate.from_cryptography--example]     |     | [from_cryptography][pki_tools.types.chain.Chain--certificatesfrom_cryptography] |
| From URI          | [from_uri][pki_tools.types.certificate.Certificate.from_uri--example]                       |     | [from_uri][pki_tools.types.chain.Chain--certificatesfrom_uri]                   |
| From Server       | [from_server][pki_tools.types.certificate.Certificate.from_server--example]                 |     | N/A                                                                             |
 
[pydantic-docs]: https://docs.pydantic.dev/latest/

[ocsp-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.2.1

[crl-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.13

[ext-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2

[loguru]: https://github.com/Delgan/loguru