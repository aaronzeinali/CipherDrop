import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_session_key(shared_secret: bytes, psk: bytes = None) -> bytes:
    """Derive 32-byte AES key from X25519 shared secret, optionally bound to PSK."""
    info = b"secure-file-transfer-v1"
    if psk:
        info += b"|psk|" + psk
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

def sha256_file(file_path: str) -> str:
    """Return SHA256 hex digest of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()
