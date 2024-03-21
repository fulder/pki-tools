# Examples

## Create CSR

```python
--8<-- "docs/examples/src/csr/create_csr.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/csr/create_csr.out"
```
///


## [InitCryptoParser.from_pem_string][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `csr_pem`
    type: tip
```
--8<-- "docs/examples/src/csr/load_csr_pem.py::17"
```
///

```python
--8<-- "docs/examples/src/csr/load_csr_pem.py:19"
```

/// details | Print output
    type: note

``` 
--8<-- "docs/examples/src/csr/load_csr_pem.out"
```
///

## [InitCryptoParser.from_file][pki_tools.types.crypto_parser.InitCryptoParser.from_file]

/// details | `csr.pem`
    type: tip
```
--8<-- "docs/examples/src/csr/csr.pem"
```
///

```python
--8<-- "docs/examples/src/csr/load_csr_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/csr/load_csr_file.out"
```
///

## [InitCryptoParser.to_file][pki_tools.types.crypto_parser.InitCryptoParser.to_file]

/// details | `chain_pem`
    type: tip
``` 
--8<-- "docs/examples/src/csr/to_file.py::17"
```
///

```python
--8<-- "docs/examples/src/csr/to_file.py:19"
```

/// details | `out_cert.pem`
    type: note
``` 
--8<-- "docs/examples/src/csr/out_csr.pem"
```
///