"""
Archipel — Module 0 : Format de Packet Binaire
Gère la sérialisation et la désérialisation des paquets selon les specs.
"""

import struct
import hashlib
import hmac
import json
from typing import Dict, Any, Tuple

MAGIC = b'ARCH'

# Types de paquets selon le sujet
TYPE_HELLO      = 0x01
TYPE_PEER_LIST  = 0x02
TYPE_MSG        = 0x03
TYPE_CHUNK_REQ  = 0x04
TYPE_CHUNK_DATA = 0x05
TYPE_MANIFEST   = 0x06
TYPE_ACK        = 0x07

# Ajoutés pour processus de connexion/handshake
TYPE_HANDSHAKE_INIT = 0x10
TYPE_HANDSHAKE_ACK  = 0x11
TYPE_HANDSHAKE_AUTH = 0x12
TYPE_PING           = 0xF0
TYPE_PONG           = 0xF1

class ArchipelPacketError(Exception):
    pass

def build_packet(pkt_type: int, node_id_hex: str, payload_bytes: bytes, hmac_key: bytes = None) -> bytes:
    """
    Construit un paquet binaire conformement à:
    MAGIC (4) | TYPE (1) | NODE_ID (32) | PAYLOAD_LEN (4) | PAYLOAD (var) | HMAC-SHA256 (32)
    """
    try:
        # Convert hex pubkey to bytes (should be 32 bytes for Ed25519)
        node_id_bytes = bytes.fromhex(node_id_hex)
        if len(node_id_bytes) != 32:
            node_id_bytes = node_id_bytes.ljust(32, b'\0')[:32]
    except ValueError:
        node_id_bytes = node_id_hex.encode("utf-8").ljust(32, b'\0')[:32]

    payload_len = len(payload_bytes)
    # En-tête de 41 octets
    header = struct.pack("!4sB32sI", MAGIC, pkt_type, node_id_bytes, payload_len)
    
    body = header + payload_bytes
    
    if hmac_key:
        signature = hmac.new(hmac_key, body, hashlib.sha256).digest()
    else:
        # Si non signé, rempli de zéros
        signature = b'\0' * 32
        
    return body + signature

def parse_packet_stream(sock) -> Tuple[int, str, bytes, bytes]:
    """
    Lit un paquet depuis un socket TCP.
    Retourne (type, node_id_hex, payload_bytes, received_hmac)
    """
    header_data = b""
    while len(header_data) < 41:
        chunk = sock.recv(41 - len(header_data))
        if not chunk:
            raise ConnectionError("Connexion fermée (en-tête incomplet)")
        header_data += chunk
        
    magic, pkt_type, node_id_bytes, payload_len = struct.unpack("!4sB32sI", header_data)
    if magic != MAGIC:
        raise ArchipelPacketError("Mauvais MAGIC byte")
        
    payload_data = b""
    while len(payload_data) < payload_len:
        chunk = sock.recv(payload_len - len(payload_data))
        if not chunk:
            raise ConnectionError("Connexion fermée (payload incomplet)")
        payload_data += chunk
        
    hmac_data = b""
    while len(hmac_data) < 32:
        chunk = sock.recv(32 - len(hmac_data))
        if not chunk:
            raise ConnectionError("Connexion fermée (HMAC incomplet)")
        hmac_data += chunk
        
    return pkt_type, node_id_bytes.hex(), payload_data, hmac_data

def parse_packet_bytes(msg: bytes) -> Tuple[int, str, bytes, bytes]:
    """Parse un paquet issu d'un datagramme UDP."""
    if len(msg) < 41 + 32:
        raise ArchipelPacketError("Paquet trop court")
    
    header = msg[:41]
    magic, pkt_type, node_id_bytes, payload_len = struct.unpack("!4sB32sI", header)
    if magic != MAGIC:
        raise ArchipelPacketError("Mauvais MAGIC byte")
        
    if len(msg) < 41 + payload_len + 32:
        raise ArchipelPacketError("Taille annoncée invalide")
        
    payload = msg[41:41+payload_len]
    hmac_data = msg[41+payload_len:41+payload_len+32]
    
    return pkt_type, node_id_bytes.hex(), payload, hmac_data

def build_json_packet(pkt_type: int, node_id_hex: str, payload_dict: Dict[str, Any]) -> bytes:
    """Helper pour envoyer un payload JSON non-chiffré."""
    payload_data = json.dumps(payload_dict).encode("utf-8")
    return build_packet(pkt_type, node_id_hex, payload_data)

def parse_json_payload(payload_bytes: bytes) -> Dict[str, Any]:
    try:
        return json.loads(payload_bytes.decode("utf-8"))
    except json.JSONDecodeError:
        return {}
