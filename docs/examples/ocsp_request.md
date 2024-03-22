# Examples

## Create OCSP Request

/// details | `cert`
    type: tip
```
--8<-- "docs/examples/src/ocsp/request/create.py::14"
```
///

```python
--8<-- "docs/examples/src/ocsp/request/create.py:16"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/ocsp/request/create.out"
```
///

## [InitCryptoParser.from_file][pki_tools.types.crypto_parser.InitCryptoParser.from_file]

/// details | `req.pem`
    type: tip
```
--8<-- "docs/examples/src/ocsp/request/req.pem"
```
///

```python
--8<-- "docs/examples/src/ocsp/request/load_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/ocsp/request/load_file.out"
```
///

## [InitCryptoParser.from_pem_string][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `pem`
    type: tip
```
--8<-- "docs/examples/src/ocsp/request/load_pem.py::8"
```
///

```python
--8<-- "docs/examples/src/ocsp/request/load_pem.py:10"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/ocsp/request/load_pem.out"
```
///

## [InitCryptoParser.to_file][pki_tools.types.crypto_parser.InitCryptoParser.to_file]

/// details | `pem`
    type: tip
``` 
--8<-- "docs/examples/src/ocsp/request/to_file.py::8"
```
///

```python
--8<-- "docs/examples/src/ocsp/request/to_file.py:10"
```

/// details | `out_req.pem`
    type: note
``` 
--8<-- "docs/examples/src/ocsp/request/out_req.pem"
```
///