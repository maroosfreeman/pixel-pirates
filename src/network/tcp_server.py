"""
Archipel — Module 1.3 : Serveur TCP d'écoute (mis à jour Sprint 2)
- Handshake X25519 avant tout échange
- Messages chiffrés AES-256-GCM après handshake
- Keep-alive ping/pong toutes les 15 secondes
- 10 connexions simultanées minimum
"""

import socket
import threading
import struct
import json
import time
import sys
from pathlib import Path

# Imports flexibles
try:
    from network.peer_table import PeerTable
except ImportError:
    src_dir = str(Path(__file__).resolve().parents[1])
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    from network.peer_table import PeerTable

try:
    from crypto.handshake import perform_handshake_responder, encode_tlv, TLV_HANDSHAKE_INIT
    from crypto.messaging import receive_encrypted_message
    from crypto.trust_store import TrustStore
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
    print("[TCP] ⚠️ Modules crypto absents — mode non chiffré")

# ── Format TLV ────────────────────────────────────────────────────

TLV_HELLO      = 0x0001
TLV_PEER_LIST  = 0x0002
TLV_PING       = 0x00F0
TLV_PONG       = 0x00F1

MAX_CONNECTIONS    = 10
KEEPALIVE_INTERVAL = 15
TCP_PORT           = 7777


def _encode_tlv(msg_type: int, payload: dict) -> bytes:
    value  = json.dumps(payload).encode()
    header = struct.pack("!HI", msg_type, len(value))
    return header + value


def _read_tlv(conn: socket.socket) -> tuple:
    """Lit un message TLV depuis un socket."""
    header = b""
    while len(header) < 6:
        chunk = conn.recv(6 - len(header))
        if not chunk:
            raise ConnectionError("Connexion fermée")
        header += chunk
    msg_type, length = struct.unpack("!HI", header)
    raw = b""
    while len(raw) < length:
        chunk = conn.recv(length - len(raw))
        if not chunk:
            raise ConnectionError("Connexion fermée")
        raw += chunk
    return msg_type, json.loads(raw.decode())


def handle_client(conn: socket.socket, addr, peer_table: PeerTable, node_id: str):
    """
    Gère une connexion TCP entrante.
    1. Attend le premier message
    2. Si HANDSHAKE_INIT → fait le handshake Sprint 2 puis échange chiffré
    3. Sinon → mode Sprint 1 (HELLO/PEER_LIST/PING/PONG)
    """
    print(f"[TCP] 🔌 Connexion entrante : {addr[0]}:{addr[1]}")
    conn.settimeout(30)

    try:
        # Lit le premier message pour savoir quel mode utiliser
        msg_type, payload = _read_tlv(conn)

        # ── Mode Sprint 2 : Handshake chiffré ────────────────────
        if msg_type == TLV_HANDSHAKE_INIT and HAVE_CRYPTO:
            print(f"[TCP] 🔐 Handshake demandé par {addr[0]}")

            # Rejoue le message dans un socket-like buffer pour handshake
            import io

            class ReplaySocket:
                """Rejoue le premier message déjà lu, puis lit depuis le vrai socket."""
                def __init__(self, first_type, first_payload, real_sock):
                    first_raw   = json.dumps(first_payload).encode()
                    first_header = struct.pack("!HI", first_type, len(first_raw))
                    self._buf  = io.BytesIO(first_header + first_raw)
                    self._sock = real_sock

                def recv(self, n):
                    data = self._buf.read(n)
                    if data:
                        return data
                    return self._sock.recv(n)

                def sendall(self, data):
                    self._sock.sendall(data)

            replay = ReplaySocket(msg_type, payload, conn)
            session = perform_handshake_responder(replay, node_id)

            # Vérifie la confiance TOFU — utilise la clé Ed25519 permanente
            # (pas la clé éphémère X25519 qui change à chaque connexion)
            trust = TrustStore()
            result = trust.verify(
                session.peer_node_id,
                session.peer_node_id,  # clé Ed25519 stable = identité permanente
            )
            if result == "mismatch":
                print(f"[TCP] 🚨 MITM détecté — connexion fermée")
                return
            if result == "revoked":
                print(f"[TCP] 🚫 Pair révoqué — connexion fermée")
                return

            print(f"[TCP] ✅ Canal sécurisé établi avec {session.peer_node_id[:16]}…")

            # Keep-alive dans un thread séparé
            def keepalive():
                while True:
                    time.sleep(KEEPALIVE_INTERVAL)
                    try:
                        conn.sendall(_encode_tlv(TLV_PING, {"ts": time.time()}))
                    except Exception:
                        break

            threading.Thread(target=keepalive, daemon=True).start()

            # Boucle de réception des messages chiffrés
            while True:
                msg = receive_encrypted_message(conn, session)
                if msg:
                    print(f"[TCP] 💬 [{addr[0]}] {msg.get('from','?')[:16]}… : {msg.get('text','')}")

        # ── Mode Sprint 1 : HELLO / PEER_LIST / PING ─────────────
        else:
            # Keep-alive
            def keepalive_s1():
                while True:
                    time.sleep(KEEPALIVE_INTERVAL)
                    try:
                        conn.sendall(_encode_tlv(TLV_PING, {"ts": time.time(), "node_id": node_id}))
                    except Exception:
                        break

            threading.Thread(target=keepalive_s1, daemon=True).start()

            # Traite le premier message déjà lu
            _dispatch(msg_type, payload, conn, addr, peer_table, node_id)

            # Continue la boucle
            while True:
                mt, pl = _read_tlv(conn)
                _dispatch(mt, pl, conn, addr, peer_table, node_id)

    except (ConnectionError, OSError):
        pass
    except Exception as e:
        print(f"[TCP] ❌ Erreur {addr[0]} : {e}")
    finally:
        conn.close()
        print(f"[TCP] 🔌 Connexion fermée : {addr[0]}:{addr[1]}")


def _dispatch(msg_type, payload, conn, addr, peer_table, node_id):
    """Dispatch des messages Sprint 1."""
    if msg_type == TLV_PING:
        conn.sendall(_encode_tlv(TLV_PONG, {"ts": time.time(), "node_id": node_id}))
        print(f"[TCP] 🏓 PONG → {addr[0]}")

    elif msg_type == TLV_PONG:
        print(f"[TCP] ✅ PONG reçu de {addr[0]}")

    elif msg_type == TLV_HELLO:
        remote_id   = payload.get("node_id")
        remote_port = payload.get("tcp_port", TCP_PORT)
        if remote_id:
            peer_table.update_peer(remote_id, addr[0], remote_port)
        peers = list(peer_table.peers.values())
        conn.sendall(_encode_tlv(TLV_PEER_LIST, {"node_id": node_id, "peers": peers}))
        print(f"[TCP] 📋 PEER_LIST → {addr[0]} ({len(peers)} pairs)")

    elif msg_type == TLV_PEER_LIST:
        for p in payload.get("peers", []):
            if p.get("node_id") and p["node_id"] != node_id:
                peer_table.update_peer(p["node_id"], p.get("ip", addr[0]), p.get("tcp_port", TCP_PORT))


class TCPServer:
    def __init__(self, peer_table: PeerTable, node_id: str, port: int = TCP_PORT):
        self.peer_table = peer_table
        self.node_id    = node_id
        self.port       = port
        self._active    = 0
        self._lock      = threading.Lock()

    def start(self):
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
                        print(f"[TCP] ⚠️ Max connexions atteint — refus {addr}")
                        conn.close()
                        continue
                    self._active += 1

                def client_thread(c, a):
                    try:
                        handle_client(c, a, self.peer_table, self.node_id)
                    finally:
                        with self._lock:
                            self._active -= 1

                threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()

        except KeyboardInterrupt:
            print("\n[TCP] Arrêt du serveur.")
        finally:
            server_sock.close()


def start_tcp_server(peer_table: PeerTable, node_id: str, port: int = TCP_PORT):
    TCPServer(peer_table=peer_table, node_id=node_id, port=port).start()


if __name__ == "__main__":
    import sys, hashlib, secrets
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    try:
        from crypto.identity import get_my_identity
        _, node_id = get_my_identity()
    except Exception:
        node_id = hashlib.sha256(secrets.token_bytes(32)).hexdigest()

    from network.peer_table import PeerTable as PT
    start_tcp_server(PT(), node_id)