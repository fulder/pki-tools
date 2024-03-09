```python
from pki_tools import Certificate, Chain

cert: Certificate = ...
chain: Chain = ...

chain.check_chain()
chain.get_issuer(cert)
```