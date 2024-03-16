from cryptography import x509

cert_pem = """
-----BEGIN CERTIFICATE-----
MIICsDCCAZigAwIBAgIUagjv68D6EIk/hIIA0mXliqJr/iIwDQYJKoZIhvcNAQEN
BQAwEjEQMA4GA1UEAwwHQ2VydCBDTjAeFw0yNDAzMDkxMzEwMTZaFw0yNDAzMTAx
MzEwMTZaMBIxEDAOBgNVBAMMB0NlcnQgQ04wggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDxw2sUZVazQcjpVN9NirPbQVLkPwIgFEQfOJwTXOhb2nofM0PA
edmVu+Kb5aw9+lZ3aJaLFOS2nFAdJ0gxINXsqdjVQ1Ok+uftWvanxql8GxDeD3sY
E92KyaRkzwyONq4dXefvRkB1j8w8gm9MbguFhZBMWlaKSqP/48mhWvJlca1zWAkY
H8moxXLcAIuvbc+qMbfNqah1LIvMkxlw1eiYogX8JPpd+OcuyPihXwIUHdl9s24S
ioqODCicBe8eegZZDfdlHQI/kyT88XqT5yHYXnhmgcjIDeCx1eAMXbVdUvzES/pi
qS7pNxvfZwLHvQsGDv7OaW+AoF7+MrunjXvtAgMBAAEwDQYJKoZIhvcNAQENBQAD
ggEBAAa6G9Xl0piwxXfVdr5gTcyHBMNfq9KzgdstTrgV38QXctiyREJW2Nu3A8mm
lsNBW+OyNOalKhYQSDrjG8D3VM6W5VfDlb2iYtBQRUfIkktSQ5/i8xifHulpHH5/
JTLMjePP+W2aOzu7o249PYnpizFsxwOWJGcF76Ouw98X/WKZMpJLSanS1hYmBrRi
vrZ+4lE8Vh4EO/pLMxktBot4cYAAYWIU6are0C4CW7LzmPRmkKcLmjxPDapEOj/d
iEEtcWJ2LNQ1UA0fzUEmrHGfasewdRpkY6K3/9psnnOOCH5T3cZfjawUq0cBpX81
C0c2MU/Ob0dcXJmIwbGA0PmIwVo=
-----END CERTIFICATE-----
"""

crypto_cert = x509.load_pem_x509_certificate(cert_pem.encode())

from pki_tools import Certificate

cert = Certificate.from_cryptography(crypto_cert)

print(cert)
