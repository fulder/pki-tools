# Examples

## Create chain
```python
--8<-- "docs/examples/src/chain/create_chain.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/chain/create_chain.out"
```
///

## [InitCryptoParser.from_pem_string][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `chain_pem`
    type: tip
```
--8<-- "docs/examples/src/chain/load_chain_pem.py::63"
```
///

```python
--8<-- "docs/examples/src/chain/load_chain_pem.py:65"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/chain/load_chain_pem.out"
```
///

## [InitCryptoParser.from_file][pki_tools.types.crypto_parser.InitCryptoParser.from_file]

/// details | `chain.pem`
    type: tip
``` 
--8<-- "docs/examples/src/chain/chain.pem"
```
///

```python
--8<-- "docs/examples/src/chain/load_chain_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/chain/load_chain_file.out"
```
///

## [InitCryptoParser.to_file][pki_tools.types.crypto_parser.InitCryptoParser.to_file]

/// details | `chain_pem`
    type: tip
``` 
--8<-- "docs/examples/src/chain/to_file.py::63"
```
///

```python
--8<-- "docs/examples/src/chain/to_file.py:65"
```

/// details | `out_cert.pem`
    type: note
``` 
--8<-- "docs/examples/src/chain/out_chain.pem"
```
///
