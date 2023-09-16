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

For main helper functions see:
[Pki Tools](https://pki-tools.fulder.dev/pki_tools/#pki-tools)