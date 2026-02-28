"""
Archipel — Test E2E entre 2 machines
Usage : python test_e2e.py <IP_MACHINE_A>
"""

import socket
import sys

sys.path.insert(0, "src")

from crypto.identity import get_my_identity
from crypto.handshake import perform_handshake_initiator
from crypto.messaging import send_encrypted_message

# ← IP de la Machine A (serveur)
IP_MACHINE_A = sys.argv[1] if len(sys.argv) > 1 else "172.20.10.3"
PORT = 7777

print(f"\n🔐 Test E2E Archipel → {IP_MACHINE_A}:{PORT}\n")

_, my_id = get_my_identity()
print(f"Mon ID : {my_id[:16]}…")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((IP_MACHINE_A, PORT))

session = perform_handshake_initiator(sock, my_id)
send_encrypted_message(sock, session, my_id, "Salut depuis Machine B — message chiffré E2E !")

print("\n✅ Message chiffré envoyé avec succès !")
print(f"   Clé de session : {session.session_key.hex()[:16]}…")
sock.close()
