from pki_tools import Certificate, Chain, is_revoked, RevokeMode

cert = Certificate.from_server("https://crt.sh/?d=16907827965")

chain = Chain.from_uri(
    [
        "http://crt.sectigo.com/SectigoPublicServerAuthenticationCAOVR36.crt",
        "https://crt.sh/?d=4256644734",
    ]
)

if is_revoked(cert, chain, revoke_mode=RevokeMode.OCSP_ONLY):
    print("Cert revoked")
