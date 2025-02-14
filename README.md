[![Python Badge](https://img.shields.io/badge/python-3.9.3%2B-7393B3.svg?logo=python&logoColor=white)](https://devguide.python.org/versions/)
[![Discord](https://img.shields.io/badge/chat-gray?logo=discord&logoColor=white)](https://discord.gg/x7k6kJC426)
[![Coverage](https://coverage-badge.samuelcolvin.workers.dev/fulder/pki-tools.svg)](https://coverage-badge.samuelcolvin.workers.dev/redirect/fulder/pki-tools)

# PKI Tools
<img src="./docs/img/icon.png" alt="pki-tools logo" style="height: 200px; width:200px;"/>

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

## Chat

[Discord Chat](https://discord.gg/x7k6kJC426)

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