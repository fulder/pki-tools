from pki_tools import Certificate, Chain, is_revoked

chain = Chain.from_uri(
    [
        "https://letsencrypt.org/certs/isrgrootx1.pem",
        "https://letsencrypt.org/certs/lets-encrypt-r3.pem",
    ]
)

valid_cert = Certificate.from_server(
    "https://valid-isrgrootx1.letsencrypt.org"
)
revoked_cert = Certificate.from_server(
    "https://revoked-isrgrootx1.letsencrypt.org"
)

print(revoked_cert)

# assert not is_revoked(valid_cert, chain)
assert is_revoked(revoked_cert, chain)
