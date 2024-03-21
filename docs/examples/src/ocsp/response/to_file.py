pem = """
-----BEGIN OCSP RESPONSE-----
MIICSAoBAKCCAkEwggI9BgkrBgEFBQcwAQEEggIuMIICKjCCARKiFgQU6+kUZ57c
x5S+dU8cqKswIZDbKxEYDzIwMjQwMzIwMjI1MTM4WjCB5jCB4zCBqTANBglghkgB
ZQMEAgMFAARAev9c8Ux9YW3pyXTHIp7Jb2rHaMP9VTyzalXWg7g+4HrIM07+qTFN
T1XNTsLb7p3DPmnwzV51hFoIgKBV0g3xUARA2cPkzXTAr1F/PS0zGg7IN962VaJn
IdqD9S4BzGCqMXqUwRC3ze8G/KMIpUHsx7r93vxS2GIJA7bisc/jdZ+LJwIUUYcX
KtFyhNcL/COZA2Hu+ur4u/ChERgPMjAyNDAzMjAyMzUxMzhaGA8yMDI0MDMyMDIz
NTEzOFqgERgPMjAyNDAzMjAyMzUxMzhaMA0GCSqGSIb3DQEBDQUAA4IBAQAoNRSK
vPnJEB8++zC1FsfMByUAUUVDKjLjkH2ObhPtcgtd4kBVtRYhpQnLu4vS/lImhRdh
99N13uoKgfdOs7GPQjkuWLiCwirmYeHjYJ4TNzQ3wkVdpLtCQPfkx5WtU5IcD8lM
aOOi+PN/rXuFo/sM0E3RV0PWu+X0zL6x1jYnVfXwc0HFHjmcALM498v2Qoet4On5
kW/Lh6+i6EUTzNWiVZ2evN7XSExqsvaXNxShAkGN1AH6M3a6DTVhDoF/948C3B/G
j40SrfyIpgfKiShWP5jUS9o5U1Vk54R6PJ22mmI1ZJZGfEj9pqbcfNgUnlC7UdML
1X93HfFsCrnOMcAh
-----END OCSP RESPONSE-----
"""

from pki_tools import OCSPResponse

req = OCSPResponse.from_pem_string(pem)

req.to_file("out_res.pem")
