![Python Badge](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=for-the-badge&logo=python)
![Chat](https://img.shields.io/badge/chat--white?style=for-the-badge&logo=discord&logoColor=white&label=chat&link=https%3A%2F%2Fdiscord.gg%2F6E6Uw7Tm)

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

## Docs

Documentation is available
at: [https://pki-tools.fulder.dev](https://pki-tools.fulder.dev)

## Main features

* [Checking Revocation][revoke-check] - checking revocation status of certificates using OCSP and/or CRL
* [Creating objects][create-objects]
* [Loading objects][load-objects]
* [Saving objects][save-objects]


[pydantic-docs]: https://docs.pydantic.dev/latest/

[ocsp-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.2.1

[crl-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.13

[ext-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2

[revoke-check]: https://pki-tools.fulder.dev/funcs/check_revocation/#pki_tools.funcs.check_revocation.is_revoked--examples

[create-objects]: https://pki-tools.fulder.dev/#creating-x509-objects

[load-objects]: https://pki-tools.fulder.dev/#loading-x509-objects

[save-objects]: https://pki-tools.fulder.dev/#saving-x509-objects