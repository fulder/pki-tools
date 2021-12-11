# crl-checker

This small python library checks if a specific certificate is revoked using the
CRL defined in the x509 CRL distribution points
extension (https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.13)

# Installation

`pip install crl-checker`

# Usage

```python
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