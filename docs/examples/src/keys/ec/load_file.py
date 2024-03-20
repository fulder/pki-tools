from pki_tools import EllipticCurveKeyPair, EllipticCurvePublicKey, EllipticCurvePrivateKey

key_pair = EllipticCurveKeyPair(
    public_key=EllipticCurvePublicKey.from_file("public.pem"),
    private_key=EllipticCurvePrivateKey.from_file("private.pem"),
)

print(key_pair)