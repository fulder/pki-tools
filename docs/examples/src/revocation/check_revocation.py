from pki_tools import Certificate, Chain, is_revoked

chain = Chain.from_uri(
    [
        "https://letsencrypt.org/certs/isrgrootx1.pem",
        "https://letsencrypt.org/certs/2024/r11.pem",
        "https://letsencrypt.org/certs/2024/r10.pem",
    ]
)

valid_cert = Certificate.from_server(
    "https://valid-isrgrootx1.letsencrypt.org"
)
revoked_cert = Certificate.from_server(
    "https://revoked-isrgrootx1.letsencrypt.org"
)


if not is_revoked(valid_cert, chain):
    print("Valid cert not revoked")

if is_revoked(revoked_cert, chain):
    print("Cert revoked")
