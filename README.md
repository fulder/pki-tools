![Python Badge](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=for-the-badge&logo=python)

PKI tools exposes a high level `cryptography` API for e.g.:

* Loading certificates from PEM strings/files/cryptography object into
  a [pydantic][pydantic-docs] model including all 
  [x509 v3 extensions][ext-draft]
* Checking revocation of certificates using [OCSP][ocsp-draft] with 
  [CRL][crl-draft] fallback

## Docs

Documentation is available
at: [https://pki-tools.fulder.dev](https://pki-tools.fulder.dev)

## Quickstart

### Install

`pip install pki-tools`

### Usage

#### Loading certificate

```python
from pki_tools import Certificate

cert_pem = """
-----BEGIN CERTIFICATE-----
<CERT_PEM_BYTES>
-----END CERTIFICATE-----
"""

cert = Certificate.from_pem_string(cert_pem)
```

#### Loading chain
```python
from pki_tools import Chain

issuer_cert_pem = """
-----BEGIN CERTIFICATE-----
<ISSUER_CERT_PEM_BYTES>
-----END CERTIFICATE-----
"""

chain = Chain.from_pem_string(issuer_cert_pem)
```

#### Checking revocation using OCSP with CRL fallback

The following example is using the `cert` and `chain` from the examples above

```python
from pki_tools import is_revoked

if is_revoked(cert, chain):
    print("Certificate Revoked!")
```

[pydantic-docs]: https://docs.pydantic.dev/latest/

[ocsp-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.2.1

[crl-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.13

[ext-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2