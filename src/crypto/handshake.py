"""
Archipel — Module 2.2 : Handshake
Échange de clés X25519 + dérivation clé de session AES-256-GCM
Forward Secrecy : nouvelle clé éphémère à chaque connexion
"""

import json
import os
import socket
import struct
import sys
from pathlib import Path

try:
    from crypto.crypto import generate_ephemeral_keypair, compute_shared_secret, derive_session_key
except ImportError:
    src_dir = str(Path(__file__).resolve().parents[1])
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    from crypto.crypto import generate_ephemeral_keypair, compute_shared_secret, derive_session_key

TLV_HANDSHAKE_INIT = 0x0003
TLV_HANDSHAKE_ACK  = 0x0004


def encode_tlv(msg_type: int, payload: dict) -> bytes:
    value  = json.dumps(payload).encode()
    header = struct.pack("!HI", msg_type, len(value))
    return header + value


def decode_tlv(sock) -> tuple:
    """Lit un message TLV depuis un socket."""
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
    def __init__(self, session_key: bytes, peer_node_id: str, peer_public_x25519: bytes):
        self.session_key        = session_key
        self.peer_node_id       = peer_node_id
        self.peer_public_x25519 = peer_public_x25519


def perform_handshake_initiator(sock, my_node_id: str) -> HandshakeSession:
    """Côté INITIATEUR — envoie INIT, attend ACK, dérive la clé."""
    my_priv, my_pub = generate_ephemeral_keypair()
    sock.sendall(encode_tlv(TLV_HANDSHAKE_INIT, {
        "node_id":       my_node_id,
        "public_x25519": my_pub.hex(),
    }))
    print(f"[HANDSHAKE] → INIT envoyé (pub: {my_pub.hex()[:16]}…)")

    msg_type, payload = decode_tlv(sock)
    if msg_type != TLV_HANDSHAKE_ACK:
        raise ValueError(f"Attendu HANDSHAKE_ACK, reçu 0x{msg_type:04X}")

    peer_node_id   = payload["node_id"]
    peer_pub_bytes = bytes.fromhex(payload["public_x25519"])
    salt           = bytes.fromhex(payload.get("salt", "")) or None

    session_key = derive_session_key(compute_shared_secret(my_priv, peer_pub_bytes), salt=salt)
    print(f"[HANDSHAKE] ✅ Session établie avec {peer_node_id[:16]}…")
    print(f"[HANDSHAKE]    Clé de session : {session_key.hex()[:16]}…")
    return HandshakeSession(session_key, peer_node_id, peer_pub_bytes)


def perform_handshake_responder(sock, my_node_id: str) -> HandshakeSession:
    """Côté RÉPONDANT — attend INIT, envoie ACK, dérive la clé."""
    msg_type, payload = decode_tlv(sock)
    if msg_type != TLV_HANDSHAKE_INIT:
        raise ValueError(f"Attendu HANDSHAKE_INIT, reçu 0x{msg_type:04X}")

    peer_node_id   = payload["node_id"]
    peer_pub_bytes = bytes.fromhex(payload["public_x25519"])
    print(f"[HANDSHAKE] ← INIT reçu de {peer_node_id[:16]}…")

    my_priv, my_pub = generate_ephemeral_keypair()
    salt = os.urandom(32)

    sock.sendall(encode_tlv(TLV_HANDSHAKE_ACK, {
        "node_id":       my_node_id,
        "public_x25519": my_pub.hex(),
        "salt":          salt.hex(),
    }))
    print(f"[HANDSHAKE] → ACK envoyé (pub: {my_pub.hex()[:16]}…)")

    session_key = derive_session_key(compute_shared_secret(my_priv, peer_pub_bytes), salt=salt)
    print(f"[HANDSHAKE] ✅ Session établie avec {peer_node_id[:16]}…")
    print(f"[HANDSHAKE]    Clé de session : {session_key.hex()[:16]}…")
    return HandshakeSession(session_key, peer_node_id, peer_pub_bytes)
