# Parsing x509 objects

## Loading from PEM

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