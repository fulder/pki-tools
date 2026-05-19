from pki_tools import Certificate

cert = Certificate.from_file("cert.pem")
print(cert)
