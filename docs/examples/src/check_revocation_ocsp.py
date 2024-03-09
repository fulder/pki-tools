from pki_tools import Certificate, Chain, is_revoked, RevokeMode

cert = Certificate.from_server("https://revoked-isrgrootx1.letsencrypt.org")

chain = Chain.from_uri(
    [
        "https://letsencrypt.org/certs/isrgrootx1.pem",
        "https://letsencrypt.org/certs/lets-encrypt-r3.pem",
    ]
)

assert is_revoked(cert, chain, revoke_mode=RevokeMode.OCSP_ONLY)
