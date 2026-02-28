"""
Archipel — Module 2.4 : Messages chiffrés E2E
AES-256-GCM + HMAC-SHA256
"""

import json
import socket
import struct
import time
import sys
from pathlib import Path

try:
    from crypto.crypto import encrypt, decrypt, compute_hmac, verify_hmac
    from crypto.handshake import HandshakeSession, encode_tlv, decode_tlv
except ImportError:
    src_dir = str(Path(__file__).resolve().parents[1])
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    from crypto.crypto import encrypt, decrypt, compute_hmac, verify_hmac
    from crypto.handshake import HandshakeSession, encode_tlv, decode_tlv

TLV_MESSAGE = 0x0010
TLV_PING    = 0x00F0
TLV_PONG    = 0x00F1


def send_encrypted_message(sock, session: HandshakeSession, my_node_id: str, text: str):
    """Envoie un message chiffré AES-256-GCM + authentifié HMAC."""
    plaintext  = json.dumps({"from": my_node_id, "text": text, "ts": time.time()}).encode()
    nonce, ct  = encrypt(session.session_key, plaintext)
    mac        = compute_hmac(session.session_key, nonce + ct)
    msg        = encode_tlv(TLV_MESSAGE, {
        "nonce":      nonce.hex(),
        "ciphertext": ct.hex(),
        "hmac":       mac.hex(),
    })
    sock.sendall(msg)
    print(f"[MSG] 📤 Message chiffré envoyé ({len(ct)} bytes)")


def receive_encrypted_message(sock, session: HandshakeSession) -> dict | None:
    """Reçoit et déchiffre un message AES-256-GCM."""
    try:
        msg_type, payload = decode_tlv(sock)
    except Exception as e:
        print(f"[MSG] ❌ Erreur réception : {e}")
        return None

    if msg_type == TLV_PING:
        sock.sendall(encode_tlv(TLV_PONG, {"ts": time.time()}))
        return None

    if msg_type != TLV_MESSAGE:
        return None

    try:
        nonce      = bytes.fromhex(payload["nonce"])
        ciphertext = bytes.fromhex(payload["ciphertext"])
        mac        = bytes.fromhex(payload["hmac"])
    except (KeyError, ValueError) as e:
        print(f"[MSG] ❌ Payload malformé : {e}")
        return None

    if not verify_hmac(session.session_key, nonce + ciphertext, mac):
        print("[MSG] 🚨 HMAC invalide — message rejeté")
        return None

    try:
        data = json.loads(decrypt(session.session_key, nonce, ciphertext).decode())
        print(f"[MSG] 📥 Message reçu de {data.get('from','?')[:16]}… : {data.get('text','')}")
        return data
    except Exception as e:
        print(f"[MSG] ❌ Déchiffrement échoué : {e}")
        return None


if __name__ == "__main__":
    import threading
    from crypto.handshake import perform_handshake_initiator, perform_handshake_responder

    print("\n🔐 Test Module 2.4 — Messages chiffrés E2E\n")

    node_alice = "alice_" + "a" * 58
    node_bob   = "bob___" + "b" * 58
    received   = {}

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 19998))
    server.listen(1)

    def bob():
        conn, _ = server.accept()
        session = perform_handshake_responder(conn, node_bob)
        received["msg"] = receive_encrypted_message(conn, session)
        conn.close()

    t = threading.Thread(target=bob)
    t.start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 19998))
    session = perform_handshake_initiator(sock, node_alice)
    send_encrypted_message(sock, session, node_alice, "Salut Bob depuis Archipel !")
    sock.close()
    t.join()
    server.close()

    assert received["msg"]["text"] == "Salut Bob depuis Archipel !"
    print("\n  ✅ Message chiffré E2E reçu correctement")
    print("\n✅ Tous les tests Module 2.4 passent !\n")
