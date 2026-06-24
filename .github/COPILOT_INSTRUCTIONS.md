Copilot instructions and developer quick-start for this repository

Purpose

This document gives short, actionable instructions that GitHub Copilot (or any AI assistant) can use to help contributors work with the pki-tools repository: run tests, run examples, and make safe changes that won't break CI.

Run environment

- This project uses [uv](https://docs.astral.sh/uv/) to manage the virtual environment and dependencies.
- Install uv (see https://docs.astral.sh/uv/getting-started/installation/), e.g.:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

- Install dependencies:

```bash
uv sync
```

Run tests and examples

- Run unit tests:

```bash
uv run --group test pytest -q
```

- Run examples (may perform network requests):

```bash
bash ./scripts/run_examples.sh
```

- To run a single example file (useful in CI debugging):

```bash
LOGURU_LEVEL=INFO uv run python3 docs/examples/src/revocation/check_revocation.py
```

Notes about examples and CI

- Examples can perform network calls and may fail in CI for reasons unrelated to code (missing network, remote changes, or mismatched chains). `scripts/run_examples.sh` contains two arrays that control behavior:
  - `skip_run`: example filenames that the runner will not execute at all
  - `exclude_outputs`: example filenames that are executed but whose stdout/stderr are redirected

- If an example historically caused CI failures, prefer to:
  - Fix the example to handle expected runtime exceptions gracefully, or
  - Keep it in `skip_run` until a full fix is implemented.

How to discover and update certificate chains in examples

When an example that loads certificates from a URL fails (e.g., `CertIssuerMissingInChain` or `FetchFailure`), the certificate chain in that example needs to be updated. This section explains how to discover the correct issuers and update the chain using `pki_tools`.

### Step 1: Fetch the end-entity certificate from the test server

Use `pki_tools` to load the cert from the server and inspect its issuer:

```python
from pki_tools import Certificate

# Example: check a revocation test server
cert = Certificate.from_server("https://revoked-isrgrootx1.letsencrypt.org")

# Print the certificate's issuer DN (Distinguished Name)
print(f"Issuer: {cert.issuer}")

# Print the issuer's CN (Common Name), which is usually the CA name
print(f"Issuer CN: {cert.issuer.cn[0] if cert.issuer.cn else 'N/A'}")
```

Output might look like:
```
Issuer: <Name(CN=Let's Encrypt YR2, O=Let's Encrypt, C=US)>
Issuer CN: YR2
```

### Step 2: Find the issuer certificate in Let's Encrypt's published list

Go to https://letsencrypt.org/certificates/ and search for the issuer CN name (e.g., "YR2"). Look for the intermediate CA section with links to `.pem` files. For each intermediate, the page lists:

- Certificate details (self-signed or cross-signed)
- Direct `.pem` download links

Example: for "Let's Encrypt YR2", the page shows:
- `Certificate details: der, pem, txt`
- With href like `/certs/gen-y/int-yr2.pem`

Copy the full URL: `https://letsencrypt.org/certs/gen-y/int-yr2.pem`

### Step 3: Resolve issuer chain recursively

Similarly, check the issuer's issuer (the parent CA):

```python
# If you have both the issuer cert and the root, load them
issuer_cert = Certificate.from_uri("https://letsencrypt.org/certs/gen-y/int-yr2.pem")
print(f"YR2's issuer: {issuer_cert.issuer}")
print(f"YR2's issuer CN: {issuer_cert.issuer.cn[0] if issuer_cert.issuer.cn else 'N/A'}")
```

Output might be:
```
YR2's issuer: <Name(CN=Root YR, O=ISRG, C=US)>
YR2's issuer CN: Root YR
```

So the chain is: `YR2 ← Root YR ← …`

### Step 4: Check the root issuer's issuer (trust anchors)

Continue up the chain to find the trust anchor:

```python
root_yr = Certificate.from_uri("https://letsencrypt.org/certs/gen-y/root-yr.pem")
print(f"Root YR's issuer: {root_yr.issuer}")
print(f"Root YR's issuer CN: {root_yr.issuer.cn[0] if root_yr.issuer.cn else 'N/A'}")
```

For a root certificate, the issuer DN will be the same as the subject DN (self-signed). The page at https://letsencrypt.org/certificates/ also lists cross-signed versions; for example, Root YR is available as:
- Self-signed: `/certs/gen-y/root-yr.pem`
- Cross-signed by ISRG Root X1: `/certs/gen-y/root-yr-by-x1.pem`

The cross-signed version is useful for compatibility with older client trust stores.

### Step 5: Build the chain and update the example

Now construct the full chain from the server's issuer up to a trusted root. For the revocation example:

```python
from pki_tools import Certificate, Chain, is_revoked

chain = Chain.from_uri(
    [
        # Include both YR1 and YR2 intermediates (some hosts may use either)
        "https://letsencrypt.org/certs/gen-y/int-yr1.pem",
        "https://letsencrypt.org/certs/gen-y/int-yr2.pem",
        # Cross-signed Root YR (for compatibility with ISRG Root X1)
        "https://letsencrypt.org/certs/gen-y/root-yr-by-x1.pem",
        # Include the trust anchor
        "https://letsencrypt.org/certs/isrgrootx1.pem",
    ]
)

cert = Certificate.from_server("https://revoked-isrgrootx1.letsencrypt.org")
if is_revoked(cert, chain):
    print("Cert revoked")
```

### Troubleshooting: Different chains for different test hosts

If an example checks multiple hosts (e.g., "valid" vs. "revoked" test servers) and they present different chains:

1. Check each host individually:
   ```python
   valid = Certificate.from_server("https://valid-isrgrootx1.letsencrypt.org")
   revoked = Certificate.from_server("https://revoked-isrgrootx1.letsencrypt.org")
   print(f"Valid issuer: {valid.issuer.cn[0] if valid.issuer.cn else 'N/A'}")
   print(f"Revoked issuer: {revoked.issuer.cn[0] if revoked.issuer.cn else 'N/A'}")
   ```

2. Include all issuers in the chain:
   ```python
   chain = Chain.from_uri([
       "https://letsencrypt.org/certs/gen-y/int-yr1.pem",
       "https://letsencrypt.org/certs/gen-y/int-yr2.pem",
       # ... other intermediates if needed
       "https://letsencrypt.org/certs/gen-y/root-yr-by-x1.pem",
       "https://letsencrypt.org/certs/isrgrootx1.pem",
   ])
   ```

### Testing and validation

After updating an example's chain:

1. Run it locally:
   ```bash
   LOGURU_LEVEL=INFO uv run python3 docs/examples/src/revocation/check_revocation.py
   ```

2. Verify it succeeds or fails with expected error (not missing certs):
   ```bash
   bash ./scripts/run_examples.sh
   ```

Changes made in this branch

- `docs/examples/src/revocation/check_revocation.py` was updated to include the correct certificate chain:
  - YR1 intermediate (`https://letsencrypt.org/certs/gen-y/int-yr1.pem`)
  - YR2 intermediate (`https://letsencrypt.org/certs/gen-y/int-yr2.pem`)
  - Root YR cross-signed by X1 (`https://letsencrypt.org/certs/gen-y/root-yr-by-x1.pem`)
  - ISRG Root X1 trust anchor (`https://letsencrypt.org/certs/isrgrootx1.pem`)
- The example now successfully validates both valid and revoked test certificates.
- `COPILOT_INSTRUCTIONS.md` was created with detailed instructions on how to discover and update certificate chains using `pki_tools`.

Guidance for Copilot prompts

When asking Copilot to modify this repository, prefer short, explicit prompts. Examples:

- "Update docs/examples/src/revocation/check_revocation.py to use the YR1 intermediate and Root YR certificate URIs from letsencrypt.org and catch CertIssuerMissingInChain so the example prints a friendly message instead of raising."

- "Add a note to scripts/run_examples.sh so that check_revocation.py is skipped in CI runs." (or the inverse: "remove from skip_run so it's executed")

- "Create or update a small README in docs/examples describing which examples require network access and how to run them locally." 

Safety checks for Copilot-generated changes

- Run `uv run --group test pytest` after code changes.
- If changing examples that perform network requests, run them locally and verify they either succeed or fail with a clear, handled error message.
- Avoid wide refactors in a single commit without tests — prefer small, testable changes.

Common troubleshooting

- Missing dependencies: ensure you ran `uv sync`.
- Import errors when running examples locally: set `PYTHONPATH` if you prefer running examples without uv, e.g. `PYTHONPATH=$(pwd) python3 ...`.

Contact

If unsure which cert URIs to use for an example, refer to https://letsencrypt.org/certificates/ and copy the exact `/certs/.../*.pem` link for the intermediate and root you want to use.

