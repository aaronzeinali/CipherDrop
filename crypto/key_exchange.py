from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

class X25519Handshake:
    """Perform X25519 ECDH handshake."""
    def __init__(self, private_key=None):
        self.private_key = private_key or x25519.X25519PrivateKey.generate()
        self.public_key_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def exchange(self, peer_public_bytes: bytes) -> bytes:
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        return self.private_key.exchange(peer_pub)
