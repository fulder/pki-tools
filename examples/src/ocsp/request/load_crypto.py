from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import ocsp, load_pem_x509_certificate

pem_cert = b"""
-----BEGIN CERTIFICATE-----
MIICsDCCAZigAwIBAgIUJDBA6chIz7alIJGj//DNL7Pq0HowDQYJKoZIhvcNAQEN
BQAwEjEQMA4GA1UEAwwHQ2VydCBDTjAeFw0yNDAzMTYxMzQzNTdaFw0yNDAzMTcx
MzQzNTdaMBIxEDAOBgNVBAMMB0NlcnQgQ04wggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDDtBdJp6oYQSIBuefvRphiau2GFGlPNvnyAm7DcVHLREiSSPX2
Ov8Krkg9/iqoZS3lcmEgj/BQMyySpJt+5Ggo60pbJBWHR86+jLBCwu687OAsfGtz
DQPN5xSWnC4K0OaUDm2doaGMcffzLL65ry/HV1XaRxxkK6HuZDt9VtyyrvSyXvMT
N0CuenLPx2b+t3owjg9wrCZghBsIQWkhCQiCN35UbEuZ3Wv3H1ezulNe0/r782NB
TXEmL6qGe/yx+//23vbmzIDar8UYEKrFNZ1yiugNWXLJKxwmxIyNtLr29MX5jrY+
yFxup5D0JTDyKRINq+dtzzLgxzPoOzMzEDZvAgMBAAEwDQYJKoZIhvcNAQENBQAD
ggEBADHeiK+JB6Z25afqGVSa1oIGEvCo8mi50/tcT+lH03Jt5x+bAKgPJGI8Gew/
0ko7JU3O8Sy3nTrVnLcgKSJiot6t7DMhWOSKTcuJTCOsr2WDgJQvF49yZfg+f5df
AWwXkraTwjJ0RoIHN/Kp0TZvgAlZhKkHFNnqT2laubjMIzeF6k/3o6HZCfBV83fu
YbzBK6rQjzFklxBN+ml2XX1aBMKYkqjbsfLpl7mAKUiZ58jxu6/FGTh6O8ffrr9z
iQBRwByulMBGxzitq/EUoTEeKvtiX5WFTetE19EE7Ojzy6c6qkNlwCjK49WF6smA
2IBk2TPLyVH4LeRc/XQi+Oj7ak0=
-----END CERTIFICATE-----
"""
cert = load_pem_x509_certificate(pem_cert)

builder = ocsp.OCSPRequestBuilder()
builder = builder.add_certificate(cert, cert, SHA256())
crypto_ocsp_request = builder.build()

from pki_tools import OCSPRequest

ocsp_request = OCSPRequest.from_cryptography(crypto_ocsp_request)

print(ocsp_request)
