"""
Archipel — Module 2.2 : Handshake
Échange de clés X25519 + dérivation clé de session AES-256-GCM
Forward Secrecy : nouvelle clé éphémère à chaque connexion
Séquence à 3 temps complète (INIT -> ACK -> AUTH)
"""

import json
import os
import socket
import struct
import sys
from pathlib import Path

try:
    from crypto.crypto import generate_ephemeral_keypair, compute_shared_secret, derive_session_key
    from network.packet import (
        build_json_packet, parse_packet_stream, parse_json_payload,
        TYPE_HANDSHAKE_INIT, TYPE_HANDSHAKE_ACK, TYPE_HANDSHAKE_AUTH
    )
except ImportError:
    src_dir = str(Path(__file__).resolve().parents[1])
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    from crypto.crypto import generate_ephemeral_keypair, compute_shared_secret, derive_session_key
    from network.packet import (
        build_json_packet, parse_packet_stream, parse_json_payload,
        TYPE_HANDSHAKE_INIT, TYPE_HANDSHAKE_ACK, TYPE_HANDSHAKE_AUTH
    )


class HandshakeSession:
    def __init__(self, session_key: bytes, peer_node_id: str, peer_public_x25519: bytes):
        self.session_key        = session_key
        self.peer_node_id       = peer_node_id
        self.peer_public_x25519 = peer_public_x25519


def perform_handshake_initiator(sock, my_node_id: str, my_signing_key=None) -> HandshakeSession:
    """Côté INITIATEUR — envoie INIT, attend ACK, envoie AUTH, dérive la clé."""
    my_priv, my_pub = generate_ephemeral_keypair()
    
    # 1. Envoi INIT
    sock.sendall(build_json_packet(TYPE_HANDSHAKE_INIT, my_node_id, {
        "public_x25519": my_pub.hex(),
    }))
    print(f"[HANDSHAKE] → INIT envoyé (pub: {my_pub.hex()[:16]}…)")

    # 2. Réception ACK
    msg_type, peer_node_id, payload_bytes, _ = parse_packet_stream(sock)
    if msg_type != TYPE_HANDSHAKE_ACK:
        raise ValueError(f"Attendu HANDSHAKE_ACK, reçu 0x{msg_type:02X}")

    payload = parse_json_payload(payload_bytes)
    peer_pub_bytes = bytes.fromhex(payload["public_x25519"])
    salt           = bytes.fromhex(payload.get("salt", "")) or None

    session_key = derive_session_key(compute_shared_secret(my_priv, peer_pub_bytes), salt=salt)
    
    # 3. Envoi AUTH (Signature Ed25519 sur la clé de session pour s'authentifier)
    if my_signing_key:
        signature = my_signing_key.sign(b"archipel-auth" + session_key).signature
    else:
        signature = b""
        
    sock.sendall(build_json_packet(TYPE_HANDSHAKE_AUTH, my_node_id, {
        "sig": signature.hex()
    }))
    print(f"[HANDSHAKE] → AUTH envoyé")

    print(f"[HANDSHAKE] ✅ Session établie avec {peer_node_id[:16]}…")
    return HandshakeSession(session_key, peer_node_id, peer_pub_bytes)


def perform_handshake_responder(sock, my_node_id: str, my_signing_key=None, first_msg_type=None, first_peer_id=None, first_payload=None) -> HandshakeSession:
    """Côté RÉPONDANT — attend INIT, envoie ACK, attend AUTH, dérive la clé."""
    
    # 1. Réception INIT (peut être passé en paramètre si déjà lu par le routeur)
    if first_msg_type is not None:
        msg_type = first_msg_type
        peer_node_id = first_peer_id
        payload = first_payload
    else:
        msg_type, peer_node_id, payload_bytes, _ = parse_packet_stream(sock)
        payload = parse_json_payload(payload_bytes)
        
    if msg_type != TYPE_HANDSHAKE_INIT:
        raise ValueError(f"Attendu HANDSHAKE_INIT, reçu 0x{msg_type:02X}")

    peer_pub_bytes = bytes.fromhex(payload["public_x25519"])
    print(f"[HANDSHAKE] ← INIT reçu de {peer_node_id[:16]}…")

    # 2. Enregistrement ACK
    my_priv, my_pub = generate_ephemeral_keypair()
    salt = os.urandom(32)

    sock.sendall(build_json_packet(TYPE_HANDSHAKE_ACK, my_node_id, {
        "public_x25519": my_pub.hex(),
        "salt":          salt.hex(),
    }))
    print(f"[HANDSHAKE] → ACK envoyé (pub: {my_pub.hex()[:16]}…)")

    session_key = derive_session_key(compute_shared_secret(my_priv, peer_pub_bytes), salt=salt)

    # 3. Attente AUTH
    msg_type, auth_peer_id, payload_bytes, _ = parse_packet_stream(sock)
    if msg_type != TYPE_HANDSHAKE_AUTH:
        raise ValueError(f"Attendu HANDSHAKE_AUTH, reçu 0x{msg_type:02X}")
        
    auth_payload = parse_json_payload(payload_bytes)
    print(f"[HANDSHAKE] ← AUTH reçu")

    if auth_peer_id != peer_node_id:
        raise ValueError("L'identité de l'émetteur a changé pendant le handshake !")
        
    # Idéalement revérifier auth_payload["sig"] avec peer_node_id (Ed25519 pubkey) ici.

    print(f"[HANDSHAKE] ✅ Session établie avec {peer_node_id[:16]}…")
    return HandshakeSession(session_key, peer_node_id, peer_pub_bytes)
