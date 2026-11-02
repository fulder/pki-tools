from pki_tools import Certificate

cert = Certificate.from_uri("https://letsencrypt.org/certs/gen-y/int-yr1.pem")

print(cert)
