import socket, struct, os, json, hashlib
from crypto.key_exchange import X25519Handshake
from crypto.crypto_utils import derive_session_key
from crypto.aes import AESGCMWrapper

CHUNK_SIZE = 4096

def send_varlen_bytes(conn, data):
    conn.sendall(struct.pack("!I", len(data)))
    if data:
        conn.sendall(data)

def recv_varlen_bytes(conn):
    raw = conn.recv(4)
    if not raw:
        return b""
    (length,) = struct.unpack("!I", raw)
    buf = b""
    while len(buf) < length:
        chunk = conn.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf

class SecureFileClient:
    def __init__(self, host, port, file_path, psk=None):
        self.host = host
        self.port = port
        self.file_path = file_path
        self.psk = psk.encode() if psk else None

    def send_file(self):
        print(f"[*] Connecting to {self.host}:{self.port}")
        handshake = X25519Handshake()
        with socket.create_connection((self.host, self.port)) as s:
            print("[*] Connected, starting handshake...")
            # 1) handshake
            send_varlen_bytes(s, handshake.public_key_bytes)
            server_pub = recv_varlen_bytes(s)
            shared_secret = handshake.exchange(server_pub)
            session_key = derive_session_key(shared_secret, self.psk)
            aes = AESGCMWrapper(session_key)
            print("[*] Handshake complete, sending file...")

            # 2) header
            filename = os.path.basename(self.file_path)
            with open(self.file_path,"rb") as f:
                file_bytes = f.read()
            filesize = len(file_bytes)
            sha256sum = hashlib.sha256(file_bytes).hexdigest()
            header = {"filename": filename, "filesize": filesize, "sha256": sha256sum}
            header_bytes = json.dumps(header).encode()
            nonce = os.urandom(12)
            send_varlen_bytes(s, nonce + aes.encrypt(header_bytes, nonce))
            print(f"[*] Header sent: {filename} ({filesize} bytes)")

            # 3) send file in chunks
            sent = 0
            for i in range(0, filesize, CHUNK_SIZE):
                chunk = file_bytes[i:i+CHUNK_SIZE]
                chunk_nonce = os.urandom(12)
                ciphertext = aes.encrypt(chunk, chunk_nonce)
                send_varlen_bytes(s, chunk_nonce + ciphertext)
                sent += len(chunk)
                print(f"\r[>] Sent {sent}/{filesize} bytes", end="", flush=True)
            print("\n[*] File sent, sending EOF...")
            send_varlen_bytes(s, b"")

            # 4) receive status
            enc_status = recv_varlen_bytes(s)
            status = json.loads(aes.decrypt(enc_status[12:], enc_status[:12]).decode())
            print("[+] Server status:", status)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Secure File Transfer Client")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--file", required=True)
    parser.add_argument("--psk", required=False)
    args = parser.parse_args()

    client = SecureFileClient(args.host, args.port, args.file, args.psk)
    client.send_file()
