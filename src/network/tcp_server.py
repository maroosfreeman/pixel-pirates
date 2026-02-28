"""
Archipel — Module 1.3 : Serveur TCP d'écoute
Port configurable via .env (défaut 7777)
Protocole TLV (Type-Length-Value) sur stream TCP
10 connexions simultanées minimum
Keep-alive ping/pong toutes les 15 secondes
"""

import socket
import threading
import struct
import json
import time
import sys
from pathlib import Path

# Import flexible pour PeerTable
try:
    from network.peer_table import PeerTable
except ImportError:
    src_dir = str(Path(__file__).resolve().parents[1])
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    from network.peer_table import PeerTable

# ── Format TLV ────────────────────────────────────────────────────
# Type   : 2 bytes (uint16 big-endian)
# Length : 4 bytes (uint32 big-endian)
# Value  : N bytes (JSON encodé)

TLV_HELLO      = 0x0001
TLV_PEER_LIST  = 0x0002
TLV_PING       = 0x00F0
TLV_PONG       = 0x00F1

MAX_CONNECTIONS   = 10
KEEPALIVE_INTERVAL = 15   # secondes entre chaque ping
TCP_PORT          = 7777


def encode_tlv(msg_type: int, payload: dict) -> bytes:
    """Encode un message en TLV."""
    value  = json.dumps(payload).encode()
    header = struct.pack("!HI", msg_type, len(value))
    return header + value


def decode_tlv(data: bytes) -> tuple:
    """Décode un message TLV. Retourne (type, payload_dict)."""
    msg_type, length = struct.unpack("!HI", data[:6])
    payload = json.loads(data[6:6 + length].decode())
    return msg_type, payload


def handle_client(conn: socket.socket, addr, peer_table: PeerTable, node_id: str):
    """
    Gère une connexion TCP entrante.
    - Reçoit les messages TLV
    - Répond aux PING par PONG
    - Répond aux HELLO par PEER_LIST
    - Keep-alive toutes les 15 secondes
    """
    print(f"[TCP] 🔌 Connexion entrante : {addr[0]}:{addr[1]}")
    conn.settimeout(KEEPALIVE_INTERVAL + 5)  # timeout légèrement supérieur au keepalive

    # Thread keep-alive — envoie un PING toutes les 15 secondes
    def keepalive_loop():
        while True:
            time.sleep(KEEPALIVE_INTERVAL)
            try:
                ping = encode_tlv(TLV_PING, {"ts": time.time(), "node_id": node_id})
                conn.sendall(ping)
                print(f"[TCP] 📡 PING envoyé à {addr[0]}:{addr[1]}")
            except Exception:
                break  # Connexion fermée, on arrête

    threading.Thread(target=keepalive_loop, daemon=True).start()

    try:
        while True:
            # Lit le header TLV (6 bytes : 2 type + 4 length)
            header = b""
            while len(header) < 6:
                chunk = conn.recv(6 - len(header))
                if not chunk:
                    return  # Connexion fermée
                header += chunk

            msg_type, length = struct.unpack("!HI", header)

            # Sécurité : rejette les messages > 1 Mo
            if length > 1_000_000:
                print(f"[TCP] ⚠️ Message trop grand ({length} bytes) — connexion fermée")
                return

            # Lit le payload
            raw = b""
            while len(raw) < length:
                chunk = conn.recv(length - len(raw))
                if not chunk:
                    return
                raw += chunk

            try:
                payload = json.loads(raw.decode())
            except json.JSONDecodeError:
                print(f"[TCP] ⚠️ Payload malformé depuis {addr[0]}")
                continue

            # ── Dispatch des messages ─────────────────────────────

            if msg_type == TLV_PING:
                # Répond immédiatement par un PONG
                pong = encode_tlv(TLV_PONG, {"ts": time.time(), "node_id": node_id})
                conn.sendall(pong)
                print(f"[TCP] 🏓 PONG envoyé à {addr[0]}:{addr[1]}")

            elif msg_type == TLV_PONG:
                print(f"[TCP] ✅ PONG reçu de {addr[0]}:{addr[1]}")

            elif msg_type == TLV_HELLO:
                # Enregistre le pair et envoie la PEER_LIST
                remote_node_id = payload.get("node_id")
                remote_port    = payload.get("tcp_port", TCP_PORT)

                if remote_node_id:
                    peer_table.update_peer(remote_node_id, addr[0], remote_port)

                # Envoie la liste des pairs connus
                peers = list(peer_table.peers.values())
                peer_list_msg = encode_tlv(TLV_PEER_LIST, {
                    "node_id": node_id,
                    "peers": peers,
                })
                conn.sendall(peer_list_msg)
                print(f"[TCP] 📋 PEER_LIST envoyée à {addr[0]} ({len(peers)} pairs)")

            elif msg_type == TLV_PEER_LIST:
                # Intègre les pairs reçus dans notre table
                peers_data = payload.get("peers", [])
                new_count  = 0
                for p in peers_data:
                    if p.get("node_id") and p.get("node_id") != node_id:
                        peer_table.update_peer(
                            p["node_id"],
                            p.get("ip", addr[0]),
                            p.get("tcp_port", TCP_PORT)
                        )
                        new_count += 1
                if new_count:
                    print(f"[TCP] 🆕 {new_count} nouveau(x) pair(s) via PEER_LIST")

            else:
                print(f"[TCP] ❓ Type inconnu : 0x{msg_type:04X}")

    except socket.timeout:
        print(f"[TCP] ⏱️ Timeout {addr[0]}:{addr[1]} — connexion fermée")
    except Exception as e:
        print(f"[TCP] ❌ Erreur avec {addr[0]}:{addr[1]} : {e}")
    finally:
        conn.close()
        print(f"[TCP] 🔌 Connexion fermée : {addr[0]}:{addr[1]}")


class TCPServer:
    """
    Serveur TCP asyncio — écoute sur le port configuré.
    Gère jusqu'à MAX_CONNECTIONS connexions simultanées.
    """

    def __init__(self, peer_table: PeerTable, node_id: str, port: int = TCP_PORT):
        self.peer_table = peer_table
        self.node_id    = node_id
        self.port       = port
        self._active    = 0
        self._lock      = threading.Lock()

    def start(self):
        """Démarre le serveur TCP en écoute."""
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(("0.0.0.0", self.port))
            server_sock.listen(MAX_CONNECTIONS)
            print(f"[TCP] 🚀 Serveur démarré sur 0.0.0.0:{self.port}")
            print(f"[TCP] 📶 Connexions simultanées max : {MAX_CONNECTIONS}")

            while True:
                conn, addr = server_sock.accept()

                with self._lock:
                    if self._active >= MAX_CONNECTIONS:
                        print(f"[TCP] ⚠️ Connexions max atteintes — refus de {addr}")
                        conn.close()
                        continue
                    self._active += 1

                # Chaque client dans son propre thread
                def client_thread(c, a):
                    try:
                        handle_client(c, a, self.peer_table, self.node_id)
                    finally:
                        with self._lock:
                            self._active -= 1

                threading.Thread(
                    target=client_thread,
                    args=(conn, addr),
                    daemon=True
                ).start()

        except KeyboardInterrupt:
            print("\n[TCP] Arrêt du serveur.")
        finally:
            server_sock.close()


def start_tcp_server(peer_table: PeerTable, node_id: str, port: int = TCP_PORT):
    """Point d'entrée simple pour lancer le serveur TCP."""
    server = TCPServer(peer_table=peer_table, node_id=node_id, port=port)
    server.start()


if __name__ == "__main__":
    # Test standalone — crée une peer table vide et lance le serveur
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    from network.peer_table import PeerTable as PT
    table   = PT()
    node_id = "test_node_" + "0" * 22  # ID factice pour test

    start_tcp_server(table, node_id)