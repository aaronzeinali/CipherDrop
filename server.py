import socket, os, struct, json, hashlib
from crypto.key_exchange import X25519Handshake
from crypto.crypto_utils import derive_session_key
from crypto.aes import AESGCMWrapper
from cryptography.hazmat.primitives import serialization

CHUNK_SIZE = 4096

def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf

def recv_varlen_bytes(conn):
    raw = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", raw)
    if length == 0:
        return b""
    return recv_exact(conn, length)

def send_varlen_bytes(conn, data):
    conn.sendall(struct.pack("!I", len(data)))
    if data:
        conn.sendall(data)

class SecureFileServer:
    def __init__(self, host, port, save_dir, psk=None):
        self.host = host
        self.port = port
        self.save_dir = save_dir
        self.psk = psk.encode() if psk else None
        os.makedirs(self.save_dir, exist_ok=True)

    def serve_forever(self):
        print(f"[+] Starting server on {self.host}:{self.port}, saving to {self.save_dir}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            print("[*] Server ready, waiting for connections...")

            try:
                while True:  # Loop واقعی برای accept
                    conn, addr = s.accept()
                    print(f"[+] Connection from {addr}")
                    try:
                        self.handle_connection(conn)
                    except Exception as e:
                        print(f"[!] Error: {e}")
                    finally:
                        conn.close()
                        print(f"[+] Connection closed: {addr}")
            except KeyboardInterrupt:
                print("\n[!] Server stopped by user")

    def handle_connection(self, conn):
        # Handshake
        server_handshake = X25519Handshake()
        send_varlen_bytes(conn, server_handshake.public_key_bytes)
        client_pub = recv_varlen_bytes(conn)
        shared_secret = server_handshake.exchange(client_pub)
        session_key = derive_session_key(shared_secret, self.psk)
        aes = AESGCMWrapper(session_key)

        # Header
        enc_header = recv_varlen_bytes(conn)
        nonce, ciphertext = enc_header[:12], enc_header[12:]
        header_plain = aes.decrypt(ciphertext, nonce)
        header = json.loads(header_plain.decode())
        filename = os.path.basename(header.get("filename", "received.file"))
        filesize = int(header.get("filesize", 0))
        expected_sha256 = header.get("sha256")

        out_path = os.path.join(self.save_dir, filename)
        print(f"[*] Incoming file: {filename} ({filesize} bytes)")

        # دریافت chunks
        hasher = hashlib.sha256()
        with open(out_path, "wb") as f:
            while True:
                chunk_data = recv_varlen_bytes(conn)
                if not chunk_data:
                    break
                chunk_nonce, ciphertext = chunk_data[:12], chunk_data[12:]
                plaintext = aes.decrypt(ciphertext, chunk_nonce)
                f.write(plaintext)
                hasher.update(plaintext)

        computed_sha256 = hasher.hexdigest()
        if expected_sha256 != computed_sha256:
            print(f"[!] SHA256 mismatch: expected={expected_sha256} computed={computed_sha256}")
        else:
            print(f"[+] SHA256 verified: {computed_sha256}")

        # ارسال status
        status_json = json.dumps({"status": "ok", "sha256": computed_sha256}).encode()
        nonce = os.urandom(12)
        send_varlen_bytes(conn, nonce + aes.encrypt(status_json, nonce))
        print("[+] Transfer finished.")
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Secure File Transfer Server")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--save-dir", required=True)
    parser.add_argument("--psk", required=False)
    args = parser.parse_args()

    server = SecureFileServer(args.host, args.port, args.save_dir, args.psk)
    server.serve_forever()