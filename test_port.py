import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 7777

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(("127.0.0.1", port))
    print(f"✅ Reussi: Le port {port} est ouvert.")
    sock.close()
except Exception as e:
    print(f"❌ Echec: Le port {port} n'est pas atteignable ({e}).")
