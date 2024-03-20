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

### Creating x509 objects

| **Certificate**                                                                                                                                                                                   | **CertificateSigningRequest**                                                | **Chain**                                               | **OCSP**                                                                                                                                               |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|---------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Create Self Signed][pki_tools.types.certificate.Certificate--create-self-signed-certificate]</br>[Create Cross Signed][pki_tools.types.certificate.Certificate--create-cross-signed-certificate] | [Create and sign][pki_tools.types.csr.CertificateSigningRequest--create-csr] | [Create from certificates][pki_tools.types.chain.Chain] | [Create request][pki_tools.types.ocsp.OCSPRequest--create-ocsp-request]</br>[Create response][pki_tools.types.ocsp.OCSPResponse--create-ocsp-response] |

| **Keypairs**                                                                     |
|----------------------------------------------------------------------------------|
| [DSA][pki_tools.types.key_pair.DSAKeyPair--generate-keypair]                     |
| [RSA][pki_tools.types.key_pair.RSAKeyPair--generate-keypair]                     |
| [EllipticCurve][pki_tools.types.key_pair.EllipticCurveKeyPair--generate-keypair] |
| [ED448][pki_tools.types.key_pair.Ed448KeyPair--generate-keypair]                 |
| [ED25519][pki_tools.types.key_pair.Ed25519KeyPair--generate-keypair]             |

### Loading x509 objects

| **Certificate**                                                                             | **CertificateSigningRequest**                                                                     | **Chain**                                                                       | OCSP                                                                                                                                                                                            |
|---------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [from_pem_string][pki_tools.types.certificate.Certificate--initcryptoparserfrom_pem_string] | [from_pem_string][pki_tools.types.csr.CertificateSigningRequest--initcryptoparserfrom_pem_string] | [from_pem_string][pki_tools.types.chain.Chain--initcryptoparserfrom_pem_string] | [Request.from_pem_string][pki_tools.types.ocsp.OCSPRequest--initcryptoparserfrom_pem_string]</br>[Response.from_pem_string][pki_tools.types.ocsp.OCSPResponse--initcryptoparserfrom_pem_string] | 
| [from_file][pki_tools.types.certificate.Certificate--initcryptoparserfrom_file]             | [from_file][pki_tools.types.csr.CertificateSigningRequest--initcryptoparserfrom_file]             | [from_file][pki_tools.types.chain.Chain--initcryptoparserfrom_file]             | [Request.from_file][pki_tools.types.ocsp.OCSPRequest--initcryptoparserfrom_file]</br>[Response.from_file][pki_tools.types.ocsp.OCSPResponse--initcryptoparserfrom_file]                         | 
| [from_cryptography][pki_tools.types.certificate.Certificate.from_cryptography--example]     | [from_cryptography][pki_tools.types.csr.CertificateSigningRequest.from_cryptography--example]     | [from_cryptography][pki_tools.types.chain.Chain--certificatesfrom_cryptography] | [Request.from_cryptography][pki_tools.types.ocsp.OCSPRequest.from_cryptography--example]</br>[Response.from_cryptography][pki_tools.types.ocsp.OCSPResponse.from_cryptography--example]         |                                                                                                                                                                                                
| [from_uri][pki_tools.types.certificate.Certificate.from_uri--example]                       | N/A                                                                                               | [from_uri][pki_tools.types.chain.Chain--certificatesfrom_uri]                   |                                                                                                                                                                                                 |
| [from_server][pki_tools.types.certificate.Certificate.from_server--example]                 | N/A                                                                                               | N/A                                                                             |                                                                                                                                                                                                 |

| **DSA**                                                                                     | **EllipticCurve**                                                                                     | **ED448**                                                                                     | **ED25519**                                                                                     | **RSA**                                                                                     |
|---------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| [from_pem_string][pki_tools.types.key_pair.DSAKeyPair--initcryptoparserfrom_pem_string]     | [from_pem_string][pki_tools.types.key_pair.EllipticCurveKeyPair--initcryptoparserfrom_pem_string]     | [from_pem_string][pki_tools.types.key_pair.Ed448KeyPair--initcryptoparserfrom_pem_string]     | [from_pem_string][pki_tools.types.key_pair.Ed25519KeyPair--initcryptoparserfrom_pem_string]     | [from_pem_string][pki_tools.types.key_pair.RSAKeyPair--initcryptoparserfrom_pem_string]     |
| [from_file][pki_tools.types.key_pair.DSAKeyPair--initcryptoparserfrom_file]                 | [from_file][pki_tools.types.key_pair.EllipticCurveKeyPair--initcryptoparserfrom_file]                 | [from_file][pki_tools.types.key_pair.Ed448KeyPair--initcryptoparserfrom_file]                 | [from_file][pki_tools.types.key_pair.Ed25519KeyPair--initcryptoparserfrom_file]                 | [from_file][pki_tools.types.key_pair.RSAKeyPair--initcryptoparserfrom_file]                 |
| [from_cryptography][pki_tools.types.key_pair.DSAKeyPair--initcryptoparserfrom_cryptography] | [from_cryptography][pki_tools.types.key_pair.EllipticCurveKeyPair--initcryptoparserfrom_cryptography] | [from_cryptography][pki_tools.types.key_pair.Ed448KeyPair--initcryptoparserfrom_cryptography] | [from_cryptography][pki_tools.types.key_pair.Ed25519KeyPair--initcryptoparserfrom_cryptography] | [from_cryptography][pki_tools.types.key_pair.RSAKeyPair--initcryptoparserfrom_cryptography] |

[pydantic-docs]: https://docs.pydantic.dev/latest/

[ocsp-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.2.1

[crl-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.13

[ext-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2

[loguru]: https://github.com/Delgan/loguru