"""
Archipel — Module 2.2 : Handshake Archipel
Échange de clés X25519 + dérivation de la clé de session AES-256-GCM
Forward Secrecy : nouvelle clé éphémère à chaque connexion

Flux :
  Initiateur                          Répondant
     │── HANDSHAKE_INIT (pub_x25519) ──►│
     │◄─ HANDSHAKE_ACK  (pub_x25519) ───│
     │    [clé de session dérivée]       │
     │══ messages chiffrés AES-GCM ════►│
"""

import json
import socket
import struct
import sys
from pathlib import Path

# Imports flexibles
try:
    from crypto.crypto import (
        generate_ephemeral_keypair,
        compute_shared_secret,
        derive_session_key,
    )
except ImportError:
    src_dir = str(Path(__file__).resolve().parents[1])
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    from crypto.crypto import (
        generate_ephemeral_keypair,
        compute_shared_secret,
        derive_session_key,
    )

try:
    from crypto.identity import get_my_identity
except ImportError:
    from crypto.identity import get_my_identity

# Types de messages TLV pour le handshake
TLV_HANDSHAKE_INIT = 0x0003
TLV_HANDSHAKE_ACK  = 0x0004


def encode_tlv(msg_type: int, payload: dict) -> bytes:
    value  = json.dumps(payload).encode()
    header = struct.pack("!HI", msg_type, len(value))
    return header + value


def decode_tlv(sock: socket.socket) -> tuple:
    """Lit un message TLV depuis un socket. Retourne (type, payload_dict)."""
    header = b""
    while len(header) < 6:
        chunk = sock.recv(6 - len(header))
        if not chunk:
            raise ConnectionError("Connexion fermée pendant le handshake")
        header += chunk

    msg_type, length = struct.unpack("!HI", header)
    raw = b""
    while len(raw) < length:
        chunk = sock.recv(length - len(raw))
        if not chunk:
            raise ConnectionError("Connexion fermée pendant la lecture du payload")
        raw += chunk

    return msg_type, json.loads(raw.decode())


class HandshakeSession:
    """
    Résultat d'un handshake réussi.
    Contient la clé de session et l'identité du pair.
    """
    def __init__(self, session_key: bytes, peer_node_id: str, peer_public_x25519: bytes):
        self.session_key        = session_key         # 32 bytes AES-256
        self.peer_node_id       = peer_node_id        # Ed25519 hex du pair
        self.peer_public_x25519 = peer_public_x25519  # Clé éphémère X25519 du pair

    def __repr__(self):
        return (
            f"HandshakeSession("
            f"peer={self.peer_node_id[:16]}…, "
            f"key={self.session_key.hex()[:16]}…)"
        )


def perform_handshake_initiator(sock: socket.socket, my_node_id: str) -> HandshakeSession:
    """
    Côté INITIATEUR du handshake.
    Envoie HANDSHAKE_INIT, attend HANDSHAKE_ACK, dérive la clé de session.
    """
    # 1. Génère une paire éphémère X25519
    my_priv, my_pub = generate_ephemeral_keypair()

    # 2. Envoie HANDSHAKE_INIT avec notre clé publique X25519 + notre node_id
    init_msg = encode_tlv(TLV_HANDSHAKE_INIT, {
        "node_id":    my_node_id,
        "public_x25519": my_pub.hex(),
    })
    sock.sendall(init_msg)
    print(f"[HANDSHAKE] → INIT envoyé (pub: {my_pub.hex()[:16]}…)")

    # 3. Attend HANDSHAKE_ACK
    msg_type, payload = decode_tlv(sock)
    if msg_type != TLV_HANDSHAKE_ACK:
        raise ValueError(f"Attendu HANDSHAKE_ACK (0x{TLV_HANDSHAKE_ACK:04X}), reçu 0x{msg_type:04X}")

    peer_node_id       = payload["node_id"]
    peer_pub_bytes     = bytes.fromhex(payload["public_x25519"])
    salt               = bytes.fromhex(payload.get("salt", ""))

    # 4. Calcule le secret partagé et dérive la clé de session
    shared_secret = compute_shared_secret(my_priv, peer_pub_bytes)
    session_key   = derive_session_key(shared_secret, salt=salt if salt else None)

    print(f"[HANDSHAKE] ✅ Session établie avec {peer_node_id[:16]}…")
    print(f"[HANDSHAKE]    Clé de session : {session_key.hex()[:16]}…")

    return HandshakeSession(
        session_key=session_key,
        peer_node_id=peer_node_id,
        peer_public_x25519=peer_pub_bytes,
    )


def perform_handshake_responder(sock: socket.socket, my_node_id: str) -> HandshakeSession:
    """
    Côté RÉPONDANT du handshake.
    Attend HANDSHAKE_INIT, répond avec HANDSHAKE_ACK, dérive la clé de session.
    """
    # 1. Attend HANDSHAKE_INIT
    msg_type, payload = decode_tlv(sock)
    if msg_type != TLV_HANDSHAKE_INIT:
        raise ValueError(f"Attendu HANDSHAKE_INIT (0x{TLV_HANDSHAKE_INIT:04X}), reçu 0x{msg_type:04X}")

    peer_node_id   = payload["node_id"]
    peer_pub_bytes = bytes.fromhex(payload["public_x25519"])
    print(f"[HANDSHAKE] ← INIT reçu de {peer_node_id[:16]}…")

    # 2. Génère sa propre paire éphémère X25519
    my_priv, my_pub = generate_ephemeral_keypair()

    # 3. Génère un salt aléatoire pour HKDF
    import os
    salt = os.urandom(32)

    # 4. Envoie HANDSHAKE_ACK
    ack_msg = encode_tlv(TLV_HANDSHAKE_ACK, {
        "node_id":       my_node_id,
        "public_x25519": my_pub.hex(),
        "salt":          salt.hex(),
    })
    sock.sendall(ack_msg)
    print(f"[HANDSHAKE] → ACK envoyé (pub: {my_pub.hex()[:16]}…)")

    # 5. Calcule le secret partagé et dérive la clé de session
    shared_secret = compute_shared_secret(my_priv, peer_pub_bytes)
    session_key   = derive_session_key(shared_secret, salt=salt)

    print(f"[HANDSHAKE] ✅ Session établie avec {peer_node_id[:16]}…")
    print(f"[HANDSHAKE]    Clé de session : {session_key.hex()[:16]}…")

    return HandshakeSession(
        session_key=session_key,
        peer_node_id=peer_node_id,
        peer_public_x25519=peer_pub_bytes,
    )


# ── Test standalone (simulation sans réseau) ──────────────────────

if __name__ == "__main__":
    print("\n🤝 Test Module 2.2 — Handshake Archipel\n")

    # Simule les deux côtés avec des sockets locaux
    import threading

    server_result = {}
    client_result = {}

    server_sock_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock_listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock_listen.bind(("127.0.0.1", 19999))
    server_sock_listen.listen(1)

    def server_thread():
        conn, _ = server_sock_listen.accept()
        server_result["session"] = perform_handshake_responder(conn, "node_bob_" + "0" * 54)
        conn.close()

    t = threading.Thread(target=server_thread)
    t.start()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", 19999))
    client_result["session"] = perform_handshake_initiator(client_sock, "node_alice_" + "0" * 53)
    client_sock.close()
    t.join()
    server_sock_listen.close()

    sess_a = client_result["session"]
    sess_b = server_result["session"]

    assert sess_a.session_key == sess_b.session_key, "❌ Clés de session différentes !"
    print(f"\n  ✅ Clés de session identiques des deux côtés !")
    print(f"  ✅ Forward Secrecy : clés éphémères X25519 utilisées\n")
