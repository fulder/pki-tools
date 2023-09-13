![Python Badge](https://img.shields.io/badge/python-3.7%2B-blue.svg?style=for-the-badge&logo=python)

# crl-checker

This small python library checks if a specific certificate is revoked using the
CRL defined in the x509 CRL distribution points
extension (https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.13)

# Installation

`pip install crl-checker`

# Usage

Checking revocation using PEM encoded certificate
```python3
from crl_checker import check_revoked, Revoked, Error

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
from crl_checker import check_revoked_crypto_cert, Revoked, Error

cert : x509.Certificate = ...

try:
    check_revoked_crypto_cert(cert)
except Revoked as e:
    print(f"Certificate revoked: {e}")
except Error as e:
    print(f"Revocation check failed. Error: {e}")
    raise
```
