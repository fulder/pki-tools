from pki_tools import Certificate, Chain, is_revoked, RevokeMode

cert = Certificate.from_server("https://revoked-isrgrootx1.letsencrypt.org")

chain = Chain.from_uri(
    [
        "https://letsencrypt.org/certs/isrgrootx1.pem",
        "https://letsencrypt.org/certs/2024/r10.pem",
    ]
)

if is_revoked(cert, chain, revoke_mode=RevokeMode.OCSP_ONLY):
    print("Cert revoked")
