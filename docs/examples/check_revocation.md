# Checking revocation

See e.g. [Loading from PEM][loading-from-pem] for information how to
get the `cert` and `chain` objects below.

```python
from pki_tools import Certificate, Chain, is_revoked

cert: Certificate = ...
chain: Chain = ...

if is_revoked(cert, chain):
    print("Certificate Revoked!")
```