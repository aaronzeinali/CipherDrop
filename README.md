CipherDrop

CipherDrop is a simple, secure file transfer application written in Python. It allows you to send files safely between a client and a server using strong encryption and integrity checks.

🚀 Features

End-to-End Encryption: Ensures that your files are securely transmitted and unreadable by anyone intercepting them.

Integrity Verification: Confirms that files arrive without corruption or tampering.

Lightweight and Simple: Minimal dependencies and straightforward setup for quick deployment.

Cross-Platform: Runs on any system with Python installed.

💡 Philosophy

In an era where digital communication is often vulnerable, CipherDrop is built with three guiding principles:

Privacy First: Your files are yours alone. Encryption ensures only the intended recipient can access them.

Simplicity Without Sacrifice: Security doesn't have to be complex. CipherDrop keeps the interface intuitive while maintaining strong protection.

Trust Through Transparency: Open-source by design, allowing anyone to inspect, improve, or audit the code.

CipherDrop embodies the belief that secure file sharing should be accessible, reliable, and transparent.

🛠️ Getting Started

Clone the repository:

git clone https://github.com/aaronzeinali/CipherDrop.git
cd CipherDrop


Install dependencies (if any):

pip install -r requirements.txt


Run the server:

python server.py


Run the client:

python client.py

📁 Usage

Select a file to send via the client.

The server receives the file, verifies its integrity, and saves it securely.

Encryption ensures that even if network traffic is intercepted, file contents remain confidential.

🤝 Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request. Focus areas include:

Improving encryption methods

Adding cross-platform GUI support

Enhancing performance and usability

📜 License

This project is open-source under the MIT License. See LICENSE
 for details.
