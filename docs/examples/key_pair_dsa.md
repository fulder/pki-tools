# Examples

## Generate keypair

```python
--8<-- "docs/examples/src/keys/dsa/create.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/dsa/create.out"
```
///

## [InitCryptoParser.from_cryptography][pki_tools.types.crypto_parser.InitCryptoParser.from_cryptography]

/// details | `crypto_keys`
    type: tip
```
--8<-- "docs/examples/src/keys/dsa/load_crypto.py::35"
```
///

```python
--8<-- "docs/examples/src/keys/dsa/load_crypto.py:37"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/dsa/load_crypto.out"
```
///

## [InitCryptoParser.from_file][pki_tools.types.crypto_parser.InitCryptoParser.from_file]

/// details | `private.pem`
    type: tip
```
--8<-- "docs/examples/src/keys/dsa/private.pem"
```
///
/// details | `public.pem`
    type: tip
```
--8<-- "docs/examples/src/keys/dsa/public.pem"
```
///

```python
--8<-- "docs/examples/src/keys/dsa/load_file.py"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/dsa/load_file.out"
```
///

## [InitCryptoParser.from_pem_string][pki_tools.types.crypto_parser.InitCryptoParser.from_pem_string]

/// details | `private_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/dsa/load_pem.py::14"
```
///
/// details | `public_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/dsa/load_pem.py:15:28"
```
///

```python
--8<-- "docs/examples/src/keys/dsa/load_pem.py:30"
```

/// details | Print output
    type: note
``` 
--8<-- "docs/examples/src/keys/dsa/load_pem.out"
```
///

## [InitCryptoParser.to_file][pki_tools.types.crypto_parser.InitCryptoParser.to_file]

/// details | `private_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/dsa/to_file.py::14"
```
///
/// details | `public_pem`
    type: tip
```
--8<-- "docs/examples/src/keys/dsa/to_file.py:15:28"
```
///

```python
--8<-- "docs/examples/src/keys/dsa/to_file.py:30"
```

/// details | `out_private.pem`
    type: note
``` 
--8<-- "docs/examples/src/keys/dsa/out_private.pem"
```
///

/// details | `out_public.pem`
    type: note
``` 
--8<-- "docs/examples/src/keys/dsa/out_public.pem"
```
///