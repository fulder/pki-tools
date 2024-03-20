# Examples

## Generate keypair

```python
--8<-- "docs/examples/src/keys/ed25519/create.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ed25519/create.out"
```
///

## [InitCryptoParser.from_cryptography][pki_tools.types.crypto_parser.InitCryptoParser.from_cryptography]

/// details | `crypto_keys`
    type: tip
```
--8<-- "docs/examples/src/keys/ed25519/load_crypto.py::17"
```
///

```python
--8<-- "docs/examples/src/keys/ed25519/load_crypto.py:19"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ed25519/load_crypto.out"
```
///

## [InitCryptoParser.from_file][pki_tools.types.crypto_parser.InitCryptoParser.from_file]

/// details | `private.pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ed25519/private.pem"
```
///
/// details | `public.pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ed25519/public.pem"
```
///

```python
--8<-- "docs/examples/src/keys/ed25519/load_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ed25519/load_file.out"
```
///

## [InitCryptoParser.from_pem_string][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `private_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ed25519/load_pem.py::5"
```
///
/// details | `public_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/ed25519/load_pem.py:6:10"
```
///

```python
--8<-- "docs/examples/src/keys/ed25519/load_pem.py:12"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/ed25519/load_pem.out"
```
///