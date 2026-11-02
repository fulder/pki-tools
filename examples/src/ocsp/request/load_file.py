from pki_tools import OCSPRequest

req = OCSPRequest.from_file("req.pem")

print(req)
