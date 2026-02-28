"""
Archipel — Module 2.4 : Messages chiffrés E2E
AES-256-GCM + HMAC-SHA256
"""

import json
import socket
import time
import sys
from pathlib import Path

try:
    from crypto.crypto import encrypt, decrypt, compute_hmac, verify_hmac
    from crypto.handshake import HandshakeSession
    from network.packet import (
        build_json_packet, parse_packet_stream, parse_json_payload, ArchipelPacketError,
        TYPE_MSG, TYPE_PING, TYPE_PONG, TYPE_CHUNK_REQ, TYPE_CHUNK_DATA, TYPE_MANIFEST
    )
except ImportError:
    src_dir = str(Path(__file__).resolve().parents[1])
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    from crypto.crypto import encrypt, decrypt, compute_hmac, verify_hmac
    from crypto.handshake import HandshakeSession
    from network.packet import (
        build_json_packet, parse_packet_stream, parse_json_payload, ArchipelPacketError,
        TYPE_MSG, TYPE_PING, TYPE_PONG, TYPE_CHUNK_REQ, TYPE_CHUNK_DATA, TYPE_MANIFEST
    )

def send_encrypted_payload(sock, session: HandshakeSession, msg_type: int, my_node_id: str, payload_dict: dict):
    """Encapsule un dict dans un message chiffré AES+HMAC selon msg_type."""
    plaintext  = json.dumps(payload_dict).encode("utf-8")
    nonce, ct  = encrypt(session.session_key, plaintext)
    mac        = compute_hmac(session.session_key, nonce + ct)
    
    pkt = build_json_packet(msg_type, my_node_id, {
        "nonce":      nonce.hex(),
        "ciphertext": ct.hex(),
        "hmac":       mac.hex(),
    })
    sock.sendall(pkt)

def send_encrypted_message(sock, session: HandshakeSession, my_node_id: str, text: str):
    """Envoie un message texte chiffré."""
    payload = {"from": my_node_id, "text": text, "ts": time.time()}
    send_encrypted_payload(sock, session, TYPE_MSG, my_node_id, payload)
    print(f"[MSG] 📤 Message chiffré envoyé")


def receive_encrypted_message(sock, session: HandshakeSession) -> tuple[int, dict] | tuple[None, None]:
    """Reçoit et déchiffre un message AES-256-GCM. Retourne (msg_type, dict)."""
    try:
        msg_type, _, payload_bytes, _ = parse_packet_stream(sock)
        payload = parse_json_payload(payload_bytes)
    except Exception as e:
        print(f"[MSG] ❌ Erreur réception : {e}")
        return None, None

    if msg_type == TYPE_PING:
        sock.sendall(build_json_packet(TYPE_PONG, session.peer_node_id, {"ts": time.time()}))
        return None, None

    # Retrait du blocage exclusif sur TYPE_MSG pour permettre d'autres types chiffrés (ex: CHUNK_DATA)
    # On présume que le reste du payload est construit avec {nonce, ciphertext, hmac}
    
    if msg_type not in (TYPE_MSG, TYPE_CHUNK_REQ, TYPE_CHUNK_DATA, TYPE_MANIFEST):
        return None, None

    try:
        nonce      = bytes.fromhex(payload["nonce"])
        ciphertext = bytes.fromhex(payload["ciphertext"])
        mac        = bytes.fromhex(payload["hmac"])
    except (KeyError, ValueError) as e:
        print(f"[MSG] ❌ Payload malformé : {e}")
        return None, None

    if not verify_hmac(session.session_key, nonce + ciphertext, mac):
        print("[MSG] 🚨 HMAC invalide — message rejeté")
        return None, None

    try:
        data = json.loads(decrypt(session.session_key, nonce, ciphertext).decode("utf-8"))
        return msg_type, data
    except Exception as e:
        print(f"[MSG] ❌ Déchiffrement échoué : {e}")
        return None, None


if __name__ == "__main__":
    import threading
    from crypto.handshake import perform_handshake_initiator, perform_handshake_responder
    from crypto.identity import get_my_identity

    print("\n🔐 Test Module 2.4 — Messages chiffrés E2E\n")

    my_signing_key, node_alice = get_my_identity()
    node_bob   = "bob___" + "b" * 58
    received   = {}

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 19998))
    server.listen(1)

    def bob():
        conn, _ = server.accept()
        session = perform_handshake_responder(conn, node_bob, None)
        msg_type, received["msg"] = receive_encrypted_message(conn, session)
        conn.close()

    t = threading.Thread(target=bob)
    t.start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 19998))
    session = perform_handshake_initiator(sock, node_alice, my_signing_key)
    send_encrypted_message(sock, session, node_alice, "Salut Bob depuis Archipel !")
    sock.close()
    t.join()
    server.close()

    assert received["msg"]["text"] == "Salut Bob depuis Archipel !"
    print("\n  ✅ Message chiffré E2E reçu correctement")
    print("\n✅ Tous les tests Module 2.4 passent !\n")
