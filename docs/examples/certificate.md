# Examples

## Create self signed certificate
```python
--8<-- "docs/examples/src/cert/create_cert_self_signed.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/cert/create_cert_self_signed.out"
```
///

## Create cross signed certificate
```python
--8<-- "docs/examples/src/cert/create_cert_cross_signed.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/cert/create_cert_cross_signed.out"
```
///

## [InitCryptoParser.from_pem_string][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `cert_pem`
    type: tip
```
--8<-- "docs/examples/src/cert/load_cert_pem.py::19"
```
///

```python
--8<-- "docs/examples/src/cert/load_cert_pem.py:21"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/cert/load_cert_pem.out"
```
///


## [InitCryptoParser.from_file][pki_tools.types.crypto_parser.InitCryptoParser.from_file]

/// details | `cert.pem`
    type: tip
``` 
--8<-- "docs/examples/src/cert/cert.pem"
```
///

```python
--8<-- "docs/examples/src/cert/load_cert_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/cert/load_cert_file.out"
```
///

## [InitCryptoParser.to_file][pki_tools.types.crypto_parser.InitCryptoParser.to_file]

/// details | `cert_pem`
    type: tip
``` 
--8<-- "docs/examples/src/cert/to_file.py::19"
```
///

```python
--8<-- "docs/examples/src/cert/to_file.py:21"
```

/// details | `out_cert.pem`
    type: note
``` 
--8<-- "docs/examples/src/cert/out_cert.pem"
```
///
