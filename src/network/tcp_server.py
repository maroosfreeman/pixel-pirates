"""
Archipel — Module 1.3 : Serveur TCP d'écoute (mis à jour Sprint 2)
- Handshake X25519 + Auth avant tout échange
- Messages chiffrés AES-256-GCM après handshake
- Keep-alive ping/pong toutes les 15 secondes
- 10 connexions simultanées minimum
"""

import socket
import threading
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
    from network.packet import (
        build_json_packet, parse_packet_stream, parse_json_payload, ArchipelPacketError,
        TYPE_HELLO, TYPE_PEER_LIST, TYPE_PING, TYPE_PONG, TYPE_HANDSHAKE_INIT,
        TYPE_MANIFEST, TYPE_CHUNK_REQ, TYPE_CHUNK_DATA, TYPE_MSG
    )
    from crypto.handshake import perform_handshake_responder
    from crypto.messaging import receive_encrypted_message, send_encrypted_payload
    from crypto.trust_store import TrustStore
    from transfer.chunking import LocalStorage, hash_data
    import base64
    HAVE_CRYPTO = True
except ImportError as e:
    HAVE_CRYPTO = False
    print(f"[TCP] ⚠️ Erreur d'importation crypto/packet : {e}")

MAX_CONNECTIONS    = 10
KEEPALIVE_INTERVAL = 15
TCP_PORT           = 7777

def handle_client(conn: socket.socket, addr, peer_table: PeerTable, node_id: str, my_signing_key=None, storage: LocalStorage=None):
    """
    Gère une connexion TCP entrante.
    1. Attend le premier message
    2. Si HANDSHAKE_INIT → fait le handshake Sprint 2 puis échange chiffré
    3. Sinon → mode Sprint 1 (HELLO/PEER_LIST/PING/PONG)
    """
    print(f"[TCP] 🔌 Connexion entrante : {addr[0]}:{addr[1]}")
    conn.settimeout(30)

    try:
        if not HAVE_CRYPTO:
            raise RuntimeError("Modules manquants")
            
        # Lit le premier message pour savoir quel mode utiliser
        msg_type, remote_node_id, payload_bytes, _ = parse_packet_stream(conn)
        payload = parse_json_payload(payload_bytes)

        # ── Mode Sprint 2 : Handshake chiffré ────────────────────
        if msg_type == TYPE_HANDSHAKE_INIT:
            print(f"[TCP] 🔐 Handshake demandé par {addr[0]}")

            # On passe directement le premier message pour éviter le ReplaySocket
            session = perform_handshake_responder(
                conn, node_id, my_signing_key, 
                first_msg_type=msg_type, first_peer_id=remote_node_id, first_payload=payload
            )

            # Vérifie la confiance TOFU — utilise la clé Ed25519 permanente
            trust = TrustStore()
            result = trust.verify(session.peer_node_id, session.peer_node_id)
            if result == "mismatch":
                print(f"[TCP] 🚨 MITM détecté — connexion fermée")
                return
            if result == "revoked":
                print(f"[TCP] 🚫 Pair révoqué — connexion fermée")
                return

            print(f"[TCP] ✅ Canal sécurisé établi avec {session.peer_node_id[:16]}…")

            # Keep-alive chiffré dans un thread séparé
            def keepalive():
                while True:
                    time.sleep(KEEPALIVE_INTERVAL)
                    try:
                        # PING Chiffré ? Ou en clair ? Le sujet demande "sur les connexions établies".
                        # On peut envoyer un PING applicatif chiffré ou non.
                        # On réutilise le packet binaire
                        conn.sendall(build_json_packet(TYPE_PING, node_id, {"ts": time.time()}))
                    except Exception:
                        break

            threading.Thread(target=keepalive, daemon=True).start()

            # Boucle de réception des messages chiffrés
            while True:
                msg_type, msg = receive_encrypted_message(conn, session)
                if not msg_type or not msg:
                    continue

                if msg_type == TYPE_MSG:
                    print(f"[TCP] 💬 [{addr[0]}] {msg.get('from','?')[:16]}… : {msg.get('text','')}")
                    
                elif msg_type == TYPE_MANIFEST:
                    print(f"[TCP] 📄 MANIFEST reçu pour {msg.get('filename')}")
                    if storage and msg.get("file_id") not in storage.files:
                        storage.init_download(msg)
                        print(f"  [TRANSFER] Rapatriement indexé, prêt à télécharger.")
                        
                elif msg_type == TYPE_CHUNK_REQ:
                    if not storage: continue
                    file_id = msg.get("file_id")
                    chunk_idx = msg.get("chunk_idx")
                    data_bytes = storage.get_chunk_data(file_id, chunk_idx)
                    if data_bytes:
                        payload = {
                            "file_id": file_id,
                            "chunk_idx": chunk_idx,
                            "data": base64.b64encode(data_bytes).decode('ascii'),
                            "chunk_hash": hash_data(data_bytes),
                            "signature": "TODO" # no formal sign here
                        }
                        send_encrypted_payload(conn, session, TYPE_CHUNK_DATA, node_id, payload)
                        print(f"[TCP] 📤 CHUNK_DATA {chunk_idx} envoyé")

        # ── Mode Sprint 1 : HELLO / PEER_LIST / PING ─────────────
        else:
            # Keep-alive Sprint 1
            def keepalive_s1():
                while True:
                    time.sleep(KEEPALIVE_INTERVAL)
                    try:
                        conn.sendall(build_json_packet(TYPE_PING, node_id, {"ts": time.time()}))
                    except Exception:
                        break

            threading.Thread(target=keepalive_s1, daemon=True).start()

            # Traite le premier message déjà lu
            _dispatch(msg_type, remote_node_id, payload, conn, addr, peer_table, node_id)

            # Continue la boucle
            while True:
                mt, rem_id, pl_bytes, _ = parse_packet_stream(conn)
                _dispatch(mt, rem_id, parse_json_payload(pl_bytes), conn, addr, peer_table, node_id)

    except (ConnectionError, OSError, ArchipelPacketError):
        pass
    except Exception as e:
        print(f"[TCP] ❌ Erreur {addr[0]} : {e}")
    finally:
        conn.close()
        print(f"[TCP] 🔌 Connexion fermée : {addr[0]}:{addr[1]}")


def _dispatch(msg_type, remote_node_id, payload, conn, addr, peer_table, node_id):
    """Dispatch des messages Sprint 1."""
    if msg_type == TYPE_PING:
        conn.sendall(build_json_packet(TYPE_PONG, node_id, {"ts": time.time()}))

    elif msg_type == TYPE_PONG:
        pass

    elif msg_type == TYPE_HELLO:
        remote_port = payload.get("tcp_port", TCP_PORT)
        if remote_node_id:
            peer_table.update_peer(remote_node_id, addr[0], remote_port)
        peers = list(peer_table.peers.values())
        conn.sendall(build_json_packet(TYPE_PEER_LIST, node_id, {"peers": peers}))
        print(f"[TCP] 📋 PEER_LIST → {addr[0]} ({len(peers)} pairs)")

    elif msg_type == TYPE_PEER_LIST:
        for p in payload.get("peers", []):
            if p.get("node_id") and p["node_id"] != node_id:
                peer_table.update_peer(p["node_id"], p.get("ip", addr[0]), p.get("tcp_port", TCP_PORT))


class TCPServer:
    def __init__(self, peer_table: PeerTable, node_id: str, my_signing_key=None, port: int = TCP_PORT, storage: LocalStorage=None):
        self.peer_table     = peer_table
        self.node_id        = node_id
        self.my_signing_key = my_signing_key
        self.port           = port
        self.storage        = storage or LocalStorage()
        self._active        = 0
        self._lock          = threading.Lock()

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
                        handle_client(c, a, self.peer_table, self.node_id, self.my_signing_key, self.storage)
                    finally:
                        with self._lock:
                            self._active -= 1

                threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()

        except KeyboardInterrupt:
            print("\n[TCP] Arrêt du serveur.")
        finally:
            server_sock.close()


def start_tcp_server(peer_table: PeerTable, node_id: str, signing_key, port: int = TCP_PORT):
    TCPServer(peer_table=peer_table, node_id=node_id, my_signing_key=signing_key, port=port).start()


if __name__ == "__main__":
    import sys, hashlib, secrets
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    try:
        from crypto.identity import get_my_identity
        signing_key, node_id = get_my_identity()
    except Exception:
        node_id = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        signing_key = None

    from network.peer_table import PeerTable as PT
    start_tcp_server(PT(), node_id, signing_key)