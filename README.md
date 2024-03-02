![Python Badge](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=for-the-badge&logo=python)

PKI tools exposes a high level `cryptography` API and wrappers for e.g.:

* Loading certificates from PEM strings/files/cryptography object into
  a [pydantic][pydantic-docs] model including all 
  [x509 v3 extensions][ext-draft]
* Checking revocation of certificates using [OCSP][ocsp-draft] with 
  [CRL][crl-draft] fallback
* Creating Certs, CSR, CRL easy with pure pydantic objects to e.g. get a 
  PEM file

## Docs

Documentation is available
at: [https://pki-tools.fulder.dev](https://pki-tools.fulder.dev)

## Quickstart

### Install

`pip install pki-tools`

### Usage

#### Loading from PEM

```python
from pki_tools import Certificate, Chain, CertificateSigningRequest

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

csr_pem= """
-----BEGIN CERTIFICATE REQUEST-----
<CSR_PEM_BYTES>
-----END CERTIFICATE REQUEST-----
"""


cert = Certificate.from_pem_string(cert_pem)
chain = Chain.from_pem_string(issuer_cert_pem)
csr = CertificateSigningRequest.from_pem_string(csr_pem)
```


#### Checking revocation using OCSP with CRL fallback

The following example uses `cert` and `chain` from the loading examples above

```python
from pki_tools import is_revoked

if is_revoked(cert, chain):
    print("Certificate Revoked!")
```

#### Creating

##### Self signed certificate
```python
import datetime
from pki_tools import (
    Certificate,
    Name,
    Validity,
    RSAKeyPair,
    SHA512,
)

name = Name(cn=["Cert CN"])

cert = Certificate(
    subject=name,
    issuer=name,
    validity=Validity(
        not_before=datetime.datetime.today(),
        not_after=datetime.datetime.today() + datetime.timedelta(days=1),
    ),
)

cert.sign(RSAKeyPair.generate(), SHA512)

print(cert.pem_string)
```

#### Create CSR

```python
from pki_tools import (
    Name,
    CertificateSigningRequest,
    RSAKeyPair,
    SHA512,
)

name = Name(cn=["Cert CN"])

csr = CertificateSigningRequest(subject=name)

csr.sign(RSAKeyPair.generate(), SHA512)

print(csr.pem_string)
```


[pydantic-docs]: https://docs.pydantic.dev/latest/

[ocsp-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.2.1

[crl-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.13

[ext-draft]: https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2