![Python Badge](https://img.shields.io/badge/python-3.7%2B-blue.svg?style=for-the-badge&logo=python)

# pki-tools

PKI tools exposes a high level `cryptography` API for e.g.:

* checking revocation of certificates:
  * using CRL defined in the x509 CRL
    distribution points extension 
    (https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.13)

# Installation

`pip install pki-tools`

# Usage

# CRL

Checking revocation using PEM encoded certificate
```python3
from pki_tools.crl import check_revoked, Revoked, Error

cert_pem = """
-----BEGIN CERTIFICATE-----
<CERTIFICATE_PEM_BYTES>
-----END CERTIFICATE-----
"""

try:
    check_revoked(cert_pem)
except Revoked as e:
    print(f"Certificate revoked: {e}")
except Error as e:
    print(f"Revocation check failed. Error: {e}")
    raise
```

Checking revocation using an already loaded cryptography [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate):

```python3
from cryptography import x509
from pki_tools.crl import check_revoked_crypto_cert, Revoked, Error

cert : x509.Certificate = ...

try:
    check_revoked_crypto_cert(cert)
except Revoked as e:
    print(f"Certificate revoked: {e}")
except Error as e:
    print(f"Revocation check failed. Error: {e}")
    raise
```