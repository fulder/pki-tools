from pki_tools import Certificate

cert = Certificate.from_uri(
    "https://letsencrypt.org/certs/lets-encrypt-r3.pem"
)

print(cert)
