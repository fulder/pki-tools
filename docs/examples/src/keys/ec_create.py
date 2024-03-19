from pki_tools import EllipticCurveKeyPair

key_pair = EllipticCurveKeyPair.generate(curve_name="SECP192R1")

print(key_pair.private_key.pem_string)
print(key_pair.public_key.pem_string)
