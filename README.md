![Python Badge](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=for-the-badge&logo=python)

# pki-tools

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

# Installation

`pip install pki-tools`

# Usage

See [Documentation](https://fulder.github.io/pki-tools/pki_tools/#pki-tools) for
available functions.

## Examples

### Checking OCSP and CRL revocation

The following examples uses PEM strings for certificate and issuer. Note that
it's possible to use
[x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
parameters instead as well
as [OcspIssuerUri](https://github.com/fulder/pki-tools/blob/main/pki_tools/types.py#L11)
type for the issuer in order to download and cache the issuer certificate.

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