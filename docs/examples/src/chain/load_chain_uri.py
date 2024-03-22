from pki_tools import Chain

chain = Chain.from_uri(
    [
        "https://letsencrypt.org/certs/isrgrootx1.pem",
        "https://letsencrypt.org/certs/lets-encrypt-r3.pem",
    ]
)

print(chain)
