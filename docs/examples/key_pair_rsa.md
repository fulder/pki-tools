# Examples

## Generate keypair

```python
--8<-- "docs/examples/src/keys/rsa/create.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/rsa/create.out"
```
///

## [InitCryptoParser.from_cryptography][pki_tools.types.crypto_parser.InitCryptoParser.from_cryptography]

/// details | `crypto_keys`
    type: tip
```
--8<-- "docs/examples/src/keys/rsa/load_crypto.py::47"
```
///

```python
--8<-- "docs/examples/src/keys/rsa/load_crypto.py:49"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/rsa/load_crypto.out"
```
///

## [InitCryptoParser.from_file][pki_tools.types.crypto_parser.InitCryptoParser.from_file]

/// details | `private.pem`
    type: tip
```
--8<-- "docs/examples/src/keys/rsa/private.pem"
```
///
/// details | `public.pem`
    type: tip
```
--8<-- "docs/examples/src/keys/rsa/public.pem"
```
///

```python
--8<-- "docs/examples/src/keys/rsa/load_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/rsa/load_file.out"
```
///

## [InitCryptoParser.from_pem_string][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `private_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/rsa/load_pem.py::29"
```
///
/// details | `public_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/rsa/load_pem.py:30:40"
```
///

```python
--8<-- "docs/examples/src/keys/rsa/load_pem.py:42"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/rsa/load_pem.out"
```
///

## [InitCryptoParser.to_file][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `private_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/rsa/to_file.py::29"
```
///

/// details | `public_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/rsa/to_file.py:30:40"
```
///

```python
--8<-- "docs/examples/src/keys/rsa/to_file.py:42"
```

/// details | `out_private.pem`
    type: note
``` 
--8<-- "docs/examples/src/keys/rsa/out_private.pem"
```
///

/// details | `out_public.pem`
    type: note
``` 
--8<-- "docs/examples/src/keys/rsa/out_public.pem"
```