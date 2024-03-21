# Examples

## Generate keypair

```python
--8<-- "docs/examples/src/keys/ed448/create.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ed448/create.out"
```
///

## [InitCryptoParser.from_cryptography][pki_tools.types.crypto_parser.InitCryptoParser.from_cryptography]

/// details | `crypto_keys`
    type: tip
```
--8<-- "docs/examples/src/keys/ed448/load_crypto.py::19"
```
///

```python
--8<-- "docs/examples/src/keys/ed448/load_crypto.py:21"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ed448/load_crypto.out"
```
///

## [InitCryptoParser.from_file][pki_tools.types.crypto_parser.InitCryptoParser.from_file]

/// details | `private.pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ed448/private.pem"
```
///
/// details | `public.pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ed448/public.pem"
```
///

```python
--8<-- "docs/examples/src/keys/ed448/load_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ed448/load_file.out"
```
///

## [InitCryptoParser.from_pem_string][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `private_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ed448/load_pem.py::6"
```
///
/// details | `public_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ed448/load_pem.py:7:12"
```
///

```python
--8<-- "docs/examples/src/keys/ed448/load_pem.py:14"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ed448/load_pem.out"
```
///

## [InitCryptoParser.to_file][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `private_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ed448/to_file.py::6"
```
///

/// details | `public_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ed448/to_file.py:7:12"
```
///

```python
--8<-- "docs/examples/src/keys/ed448/to_file.py:14"
```

/// details | `out_private.pem`
    type: note
``` 
--8<-- "docs/examples/src/keys/ed448/out_private.pem"
```
///

/// details | `out_public.pem`
    type: note
``` 
--8<-- "docs/examples/src/keys/ed448/out_public.pem"
```