pem = """
-----BEGIN OCSP REQUEST-----
MIG1MIGyMIGvMIGsMIGpMA0GCWCGSAFlAwQCAwUABEB6/1zxTH1hbenJdMcinslv
asdow/1VPLNqVdaDuD7gesgzTv6pMU1PVc1OwtvuncM+afDNXnWEWgiAoFXSDfFQ
BEDxuEQwiwNp5nD/Qc/BXaFEWVE7EPBp9WA/65jQSZcEmCO665C+92G+BPaoI/EE
Fl+npz50sv7HrqDeJrU+WZCFAhRPA+Kc1W3fBuNfGzu5tzF2tjo7Yw==
-----END OCSP REQUEST-----
"""

from pki_tools import OCSPRequest

req = OCSPRequest.from_pem_string(pem)

print(req)
