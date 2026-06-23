from pki_tools import Chain

chain = Chain.from_uri(
    [
        "https://letsencrypt.org/certs/gen-y/int-yr1.pem",
        "https://letsencrypt.org/certs/gen-y/root-yr-by-x1.pem",
        "https://letsencrypt.org/certs/isrgrootx1.pem",
    ]
)

print(chain)
