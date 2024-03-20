from pki_tools import Ed25519KeyPair, Ed25519PublicKey, Ed25519PrivateKey

key_pair = Ed25519KeyPair(
    public_key=Ed25519PublicKey.from_file("public.pem"),
    private_key=Ed25519PrivateKey.from_file("private.pem"),
)

print(key_pair)