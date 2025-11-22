from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESGCMWrapper:
    """Simple wrapper for AES-GCM encryption/decryption."""
    def __init__(self, key: bytes):
        self.aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, nonce: bytes) -> bytes:
        return self.aesgcm.encrypt(nonce, plaintext, None)

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        return self.aesgcm.decrypt(nonce, ciphertext, None)
