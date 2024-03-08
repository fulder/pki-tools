
## Loading Chain

### From file

```python
from pki_tools import Chain

chain = Chain.from_file("/path/to/chain.pem")
```

### From PEM

```python
from pki_tools import Chain

pem_string="-----BEGIN CERTIFICATE-----...."
chain = Chain.from_pem_string(pem_string)
```

### From URI

```python
from pki_tools import Chain

chain = Chain.from_uri("https://chain.domain/chain.pem")
```

## Using chain

```python
from pki_tools import Certificate, Chain

cert: Certificate = ...
chain: Chain = ...

chain.check_chain()
chain.get_issuer(cert)
```