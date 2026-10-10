from pki_tools import Ed448KeyPair, Ed448PrivateKey, Ed448PublicKey

key_pair = Ed448KeyPair(
    public_key=Ed448PublicKey.from_file("public.pem"),
    private_key=Ed448PrivateKey.from_file("private.pem"),
)

print(key_pair)
