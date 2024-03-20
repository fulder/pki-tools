# Examples

## Create OCSP Response

/// details | `cert`
    type: tip
```
--8<-- "docs/examples/src/ocsp/response/create.py::15"
```
///

```python
--8<-- "docs/examples/src/ocsp/response/create.py:17"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/ocsp/response/create.out"
```
///

## [InitCryptoParser.from_file][pki_tools.types.crypto_parser.InitCryptoParser.from_file]

/// details | `res.pem`
    type: tip
```
--8<-- "docs/examples/src/ocsp/response/res.pem"
```
///

```python
--8<-- "docs/examples/src/ocsp/response/load_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/ocsp/response/load_file.out"
```
///

## [InitCryptoParser.from_pem_string][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `pem`
    type: tip
```
--8<-- "docs/examples/src/ocsp/response/load_pem.py::17"
```
///

```python
--8<-- "docs/examples/src/ocsp/response/load_pem.py:19"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/ocsp/response/load_pem.out"
```
///