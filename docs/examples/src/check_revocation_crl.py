from pki_tools import Certificate, Chain, is_revoked, RevokeMode

cert = Certificate.from_uri(
    "https://letsencrypt.org/certs/lets-encrypt-r3.pem"
)

chain = Chain.from_uri(
    [
        "https://letsencrypt.org/certs/isrgrootx1.pem",
    ]
)

if is_revoked(cert, chain, revoke_mode=RevokeMode.CRL_ONLY):
    print("Certificate Revoked!")
