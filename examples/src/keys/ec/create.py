from pki_tools import EllipticCurveKeyPair, EllipticCurveName

key_pair = EllipticCurveKeyPair.generate(
    curve_name=EllipticCurveName.SECP521R1
)

print(key_pair.private_key.pem_string)
print(key_pair.public_key.pem_string)
