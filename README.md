![Python Badge](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=for-the-badge&logo=python)

PKI tools exposes a high level `cryptography` API for e.g.:

* checking revocation of certificates:
    * using CRL defined in the x509 CRL
      distribution points extension
      (https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.13)
    * using OCSP defined in the x509 Authority Information Access extension
      (https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.2.1)
* loading certificates from PEM format
* saving certificates to files
* reading certificates from files

## Docs

Documentation is available at: [https://pki-tools.fulder.dev](https://pki-tools.fulder.dev)

## Quickstart

### Install
`pip install pki-tools`

### Usage

#### Checking OCSP and CRL revocation

```python
from pki_tools import is_revoked
from pki_tools.types import PemCert

cert_pem = """
-----BEGIN CERTIFICATE-----
<CERT_PEM_BYTES>
-----END CERTIFICATE-----
"""
issuer_cert_pem = """
-----BEGIN CERTIFICATE-----
<ISSUER_CERT_PEM_BYTES>
-----END CERTIFICATE-----
"""

if is_revoked(PemCert(cert_pem), PemCert(issuer_cert_pem)):
    print("Certificate Revoked!")
```

For more functions see:
[Pki Tools](https://pki-tools.fulder.dev/pki_tools/#pki-tools)

