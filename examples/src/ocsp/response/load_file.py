from pki_tools import OCSPResponse

req = OCSPResponse.from_file("res.pem")

print(req)
