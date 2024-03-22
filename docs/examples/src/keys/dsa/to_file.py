private_pem = """
-----BEGIN DSA PRIVATE KEY-----
MIIBvAIBAAKBgQD43Od5Ib9Gf7zn3BqonOwCMvmWw3QBVSkcIIPtfjoPCF5eZUkE
+NxkC+8TVLFP6BirpwifJsUyD2SOZre2JtF3SUmKFiPhS3934suqEWHpedeZy8Dy
2g7yuqU3OiOMU06iRemDhcWJmCp3MEF5N321Eh66t9yq5oN1iYbnRkvxFQIVANAA
0DyNl0WkdNjOwKRXKtRtgf5zAoGBAKIGG/O5f1FbUmhBK0z2jZLYvup3CKSMYvJL
ztDMSjDW1NTuht0qQLszEso82SwtuYRRAvpezwkWKhQSj2fo+Dg+A8+4Rc6N9oMO
f0ZM4BOGdkm4WEKpIArx9wEYamHpGuIYSER0ygbw/vQD0fjG24FxhBKCkd7F1pf9
+ervHU/gAoGBANSn6Svi4CZns0W5Uv3yzR9+4jjUDXaHq3/1cCaAuKJF5jR7OlTf
e+n1IZCrPSshMF210wKl2LVp1NXxZLMA7sKy+2g6k3yuI65VieTAtvnh9zg+y53+
XxyYrJYvKRUmYqIluUvVDiJCJlYZdcZfgOP68v62uFDny0lY6Ow+47ZKAhRtGeN4
19EKC+vetSlF1/ORPoDQ2A==
-----END DSA PRIVATE KEY-----
"""
public_pem = """
-----BEGIN PUBLIC KEY-----
MIIBuDCCASwGByqGSM44BAEwggEfAoGBAPjc53khv0Z/vOfcGqic7AIy+ZbDdAFV
KRwgg+1+Og8IXl5lSQT43GQL7xNUsU/oGKunCJ8mxTIPZI5mt7Ym0XdJSYoWI+FL
f3fiy6oRYel515nLwPLaDvK6pTc6I4xTTqJF6YOFxYmYKncwQXk3fbUSHrq33Krm
g3WJhudGS/EVAhUA0ADQPI2XRaR02M7ApFcq1G2B/nMCgYEAogYb87l/UVtSaEEr
TPaNkti+6ncIpIxi8kvO0MxKMNbU1O6G3SpAuzMSyjzZLC25hFEC+l7PCRYqFBKP
Z+j4OD4Dz7hFzo32gw5/RkzgE4Z2SbhYQqkgCvH3ARhqYeka4hhIRHTKBvD+9APR
+MbbgXGEEoKR3sXWl/356u8dT+ADgYUAAoGBANSn6Svi4CZns0W5Uv3yzR9+4jjU
DXaHq3/1cCaAuKJF5jR7OlTfe+n1IZCrPSshMF210wKl2LVp1NXxZLMA7sKy+2g6
k3yuI65VieTAtvnh9zg+y53+XxyYrJYvKRUmYqIluUvVDiJCJlYZdcZfgOP68v62
uFDny0lY6Ow+47ZK
-----END PUBLIC KEY-----
"""

from pki_tools import DSAKeyPair, DSAPublicKey, DSAPrivateKey

key_pair = DSAKeyPair(
    public_key=DSAPublicKey.from_pem_string(public_pem),
    private_key=DSAPrivateKey.from_pem_string(private_pem),
)

key_pair.public_key.to_file("out_public.pem")
key_pair.private_key.to_file("out_private.pem")
