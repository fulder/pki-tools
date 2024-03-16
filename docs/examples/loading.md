# Loading objects

All classes implementing the 
[InitCryptoParser][pki_tools.types.crypto_parser.InitCryptoParser]
can be loaded and saved into the 
[Encoding][pki_tools.types.crypto_parser.Encoding]
formats.

## Certificate

### From PEM string (InitCryptoParser)

/// details | `cert_pem`
    type: tip
```
--8<-- "docs/examples/src/load_cert_pem.py::19"
```
///

```python
--8<-- "docs/examples/src/load_cert_pem.py:21"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/load_cert_pem.out"
```
///


### From PEM file (InitCryptoParser)

/// details | `cert.pem`
    type: tip
``` 
--8<-- "docs/examples/src/cert.pem"
```
///

```python
--8<-- "docs/examples/src/load_cert_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/load_cert_file.out"
```
///

### From URI
```python
--8<-- "docs/examples/src/load_cert_uri.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/load_cert_uri.out"
```
///

### From server
```python
--8<-- "docs/examples/src/load_cert_server.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/load_cert_server.out"
```
///


### From cryptography

/// details | `crypto_cert`
    type: tip
```
--8<-- "docs/examples/src/load_cert_crypto.py::23"
```
///

```python
--8<-- "docs/examples/src/load_cert_crypto.py:25"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/load_cert_crypto.out"
```
///

## Chain

### From PEM (InitCryptoParser)

/// details | `chain_pem`
    type: tip
```
--8<-- "docs/examples/src/load_chain_pem.py::63"
```
///

```python
--8<-- "docs/examples/src/load_chain_pem.py:65"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/load_chain_pem.out"
```
///

### From URI
```python
--8<-- "docs/examples/src/load_chain_uri.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/load_chain_uri.out"
```
///

### From file (InitCryptoParser)

/// details | `chain.pem`
    type: tip
``` 
--8<-- "docs/examples/src/chain.pem"
```
///

```python
--8<-- "docs/examples/src/load_chain_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/load_chain_file.out"
```
///

### From cryptography
/// details | `chain_pem`
    type: tip
```
--8<-- "docs/examples/src/load_chain_crypto.py::67"
```
///

```python
--8<-- "docs/examples/src/load_chain_crypto.py:69"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/load_chain_crypto.out"
```
///

