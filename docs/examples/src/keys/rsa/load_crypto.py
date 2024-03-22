from cryptography.hazmat.primitives import serialization

private_key_pem = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3/BWC4F4xtU+dSJ2oGbibuA8CWLNUJ13Y6ZjsYBE8eJyJklU
F2pnuCNe/7NldFTNhv0SF0avR8caYSQFy9S9b+Zn1QWr78Lb5vlRAXSJzIF5JoDr
DdcWgMbdVosNsvoaEOi0wRVmDbgnaWdR72OrG02C2Yw6+odAwJ+mcKHgqpAv3ERP
Z5mOWdQEm2ibdDIl4q9HOdnMokxbGsB5GqZMfdbSpGAY43gOQ9Apk+VsmB98Ws2K
Nq2S79aYw8SpRwDaZ1/c4pq24Py8TmSyvDKF4gRcAh1FC00tZXlBLiO+XP2gy1Vc
p3RR6ec/X5htYEnKI8eY3XXqRTNmrELOyvKDXwIDAQABAoIBAFwisgRB3MNR8USY
TV5pdjhQIeNqtza30us5BkN9luA+XuDJwsNvkAT+6JMj6FYYngcwEEVrW6qYjI3z
GD9o5BgqIAZRMxCOh5NceKu0mw19J69j01H6cNPC/kYhKB2/MQJL/DKE71wtrGl9
jQSFaVzuYyvGum1hQI8AIKaus5T4wLjawIfoKAHwt3T5JP3bHbifiTOordw+n3/z
B1ZnYAkot1ySzhNm8fKJuyFkowmWxUnJiHZU5T66n7MMlh4ABXtoV4ULcBns1/Qg
7yiizwrLSIfUO6/Lt66UWNNIhJjkfaUdTfYj5upfBOJoMWHUTkmW8wzneb9g9F+K
40pHmiECgYEA+x9G2J/WmkGDCQuo1/MQxf2pf3erElaSZYm9wQUHMAq96mDosQRN
Dk6MgwhmavZEqrad2pwflnY8u6kuQYtbMu1nv7TsjsdBAf2Vp5XbyM1mEcjzPZ8U
4QN6/XSQ2npaYvqqmaCO3KdaZP7Q9RAO2nQTJYAE/s8LWTwz4p7aWbUCgYEA5Enj
XGY7MCdslA8xVTrfac8ZIYryXliFGSn+gq0CIX7TLWgX3pp/JKEcexuoSGZAm1Re
6E3UPzQRM3JZQHqI8uc/mJbPL3R9ArpMmdATS5djNG7kzWTvH1vXOvSwx2O1rIod
1u6S2Vg3abAj1LqpmU9FSYQnOFZEuiaBNIGqhUMCgYEAn9Gm+AS5wpCBAYe/HDig
azFl5y7U3CXmo+KGtkop6eRcO8cTMF1pYPqSqG33KIm05+SzD8cev1Zejpw8SRCU
qRO4XKSbjL6427h0vyQ7rU8zb4wxaf1Nf2sEojvGWJVX4vhfDMjHQxzrBa26dMyU
d2k6KjqQc053jYIoD0lD86UCgYAqqDvZyiiJKPS6/dPED0or5UzW3bXIN1Y3i4dJ
N7bMN3ySYX8EU24qlAhUYKijTqgH3k4VrmVYogwMxvMyfzMT4G4bvyJbxbKOTe1+
WEkiuNkKtSX/0zpza5/eHlbiCxmpce19efrqrfc8wnMPjwmd4hgaUp1Zg5U4C3Xd
L9WDLQKBgQChdIv3B9cxyU2yGpET3/bxdLIInhJQ6vi2vGtlaIsuzPEMgxRyJZG3
TNgNLW052w0tnMGq4BWjZM2GpONwDwHzWyqVMrWXzdzU6XJTQRKxQZg4p/QVZBW0
8iQGzFv2pa+taKWUXM16eYVcs4MuRoigvosKRJNGLlJAIRB7qHEbdA==
-----END RSA PRIVATE KEY-----
"""
public_key_pem = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3/BWC4F4xtU+dSJ2oGbi
buA8CWLNUJ13Y6ZjsYBE8eJyJklUF2pnuCNe/7NldFTNhv0SF0avR8caYSQFy9S9
b+Zn1QWr78Lb5vlRAXSJzIF5JoDrDdcWgMbdVosNsvoaEOi0wRVmDbgnaWdR72Or
G02C2Yw6+odAwJ+mcKHgqpAv3ERPZ5mOWdQEm2ibdDIl4q9HOdnMokxbGsB5GqZM
fdbSpGAY43gOQ9Apk+VsmB98Ws2KNq2S79aYw8SpRwDaZ1/c4pq24Py8TmSyvDKF
4gRcAh1FC00tZXlBLiO+XP2gy1Vcp3RR6ec/X5htYEnKI8eY3XXqRTNmrELOyvKD
XwIDAQAB
-----END PUBLIC KEY-----
"""

crypto_public_key = serialization.load_pem_public_key(public_key_pem)
crypto_private_key = serialization.load_pem_private_key(
    private_key_pem, password=None
)

from pki_tools import RSAKeyPair, RSAPublicKey, RSAPrivateKey

key_pair = RSAKeyPair(
    public_key=RSAPublicKey.from_cryptography(crypto_public_key),
    private_key=RSAPrivateKey.from_cryptography(crypto_private_key),
)

print(key_pair)
