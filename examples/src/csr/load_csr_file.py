from pki_tools import CertificateSigningRequest

csr = CertificateSigningRequest.from_file("csr.pem")

print(csr)
