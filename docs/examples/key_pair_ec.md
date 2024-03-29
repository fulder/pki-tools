# Examples

## Generate keypair

```python
--8<-- "docs/examples/src/keys/ec/create.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ec/create.out"
```
///

## [InitCryptoParser.from_cryptography][pki_tools.types.crypto_parser.InitCryptoParser.from_cryptography]

/// details | `crypto_keys`
    type: tip
```
--8<-- "docs/examples/src/keys/ec/load_crypto.py::20"
```
///

```python
--8<-- "docs/examples/src/keys/ec/load_crypto.py:22"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ec/load_crypto.out"
```
///

## [InitCryptoParser.from_file][pki_tools.types.crypto_parser.InitCryptoParser.from_file]

/// details | `private.pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ec/private.pem"
```
///
/// details | `public.pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ec/public.pem"
```
///

```python
--8<-- "docs/examples/src/keys/ec/load_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ec/load_file.out"
```
///

## [InitCryptoParser.from_pem_string][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `private_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ec/load_pem.py::7"
```
///
/// details | `public_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ec/load_pem.py:8:13"
```
///

```python
--8<-- "docs/examples/src/keys/ec/load_pem.py:15"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ec/load_pem.out"
```
///

## [InitCryptoParser.to_file][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `private_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ec/to_file.py::7"
```
///

/// details | `public_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ec/to_file.py:8:13"
```
///

```python
--8<-- "docs/examples/src/keys/ec/to_file.py:15"
```

/// details | `out_private.pem`
    type: note
``` 
--8<-- "docs/examples/src/keys/ec/out_private.pem"
```
///

/// details | `out_public.pem`
    type: note
``` 
--8<-- "docs/examples/src/keys/ec/out_public.pem"
```
///