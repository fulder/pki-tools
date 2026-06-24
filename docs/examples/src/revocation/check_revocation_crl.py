from pki_tools import Certificate, Chain, is_revoked, RevokeMode

cert = Certificate.from_uri("https://letsencrypt.org/certs/gen-y/int-yr1.pem")

chain = Chain.from_uri(
    [
        "https://letsencrypt.org/certs/gen-y/root-yr-by-x1.pem",
        "https://letsencrypt.org/certs/isrgrootx1.pem",
    ]
)

if not is_revoked(cert, chain, revoke_mode=RevokeMode.CRL_ONLY):
    print("Cert not revoked")
