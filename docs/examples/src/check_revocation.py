from pki_tools import Certificate, Chain, is_revoked

cert = Certificate.from_server("https://revoked-isrgrootx1.letsencrypt.org")

chain = Chain.from_uri(
    [
        "https://letsencrypt.org/certs/isrgrootx1.pem",
        "https://letsencrypt.org/certs/lets-encrypt-r3.pem",
    ]
)

if is_revoked(cert, chain):
    print("Certificate Revoked!")
