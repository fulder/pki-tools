pem = """
-----BEGIN OCSP REQUEST-----
MIG1MIGyMIGvMIGsMIGpMA0GCWCGSAFlAwQCAwUABEB6/1zxTH1hbenJdMcinslv
asdow/1VPLNqVdaDuD7gesgzTv6pMU1PVc1OwtvuncM+afDNXnWEWgiAoFXSDfFQ
BEDnCmRUwFymLe1CkhH/iY+y03tK/R5ACKvX2BSe/sWnXrHtW4whiQowmpxQPlvN
od+22kNsyj67c0Rb/m76j/gSAhRX1AhPCGDVeO5pEcsQ+BDt4x5LMQ==
-----END OCSP REQUEST-----
"""

from pki_tools import OCSPRequest

req = OCSPRequest.from_pem_string(pem)

req.to_file("out_req.pem")
