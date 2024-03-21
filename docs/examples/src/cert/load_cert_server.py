from pki_tools import Certificate

cert = Certificate.from_server("https://revoked-isrgrootx1.letsencrypt.org")

print(cert)
