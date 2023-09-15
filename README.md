![Python Badge](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=for-the-badge&logo=python)

# pki-tools

PKI tools exposes a high level `cryptography` API for e.g.:

* checking revocation of certificates:
  * using CRL defined in the x509 CRL
    distribution points extension 
    (https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.13)
  * using OCSP defined in the x509 Authority Information Access extension
    (https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.2.1)
* loading certificates


# Installation

`pip install pki-tools`
