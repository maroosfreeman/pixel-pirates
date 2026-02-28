"""
Archipel — Module 3.2 & 3.3 : Transfer Manager
Gère l'envoi et la réception des chunks via TCP chiffré AES-256-GCM.
Protocole : FILE_MANIFEST → CHUNK_REQ → CHUNK_DATA → CHUNK_ACK
Utilise le format de paquet natif Archipel (network.packet)
"""

import base64
import json
import socket
import threading
import time
import sys
from pathlib import Path

# Import flexible — fonctionne avec python -m src.transfer.X et python transfer_manager.py
try:
    from transfer.chunking import LocalStorage, hash_data, CHUNK_SIZE
except ImportError:
    try:
        from src.transfer.chunking import LocalStorage, hash_data, CHUNK_SIZE
    except ImportError:
        src_dir = str(Path(__file__).resolve().parents[1])
        if src_dir not in sys.path:
            sys.path.insert(0, src_dir)
        from transfer.chunking import LocalStorage, hash_data, CHUNK_SIZE

try:
    from network.packet import (
        build_json_packet, parse_packet_stream, parse_json_payload,
        TYPE_CHUNK_REQ, TYPE_CHUNK_DATA, TYPE_MANIFEST, TYPE_ACK,
    )
    from crypto.handshake import perform_handshake_initiator, perform_handshake_responder
    from crypto.crypto import encrypt, decrypt, compute_hmac, verify_hmac
    from crypto.identity import get_my_identity
except ImportError:
    try:
        from src.network.packet import (
            build_json_packet, parse_packet_stream, parse_json_payload,
            TYPE_CHUNK_REQ, TYPE_CHUNK_DATA, TYPE_MANIFEST, TYPE_ACK,
        )
        from src.crypto.handshake import perform_handshake_initiator, perform_handshake_responder
        from src.crypto.crypto import encrypt, decrypt, compute_hmac, verify_hmac
        from src.crypto.identity import get_my_identity
    except ImportError:
        src_dir = str(Path(__file__).resolve().parents[1])
        if src_dir not in sys.path:
            sys.path.insert(0, src_dir)
        from network.packet import (
            build_json_packet, parse_packet_stream, parse_json_payload,
            TYPE_CHUNK_REQ, TYPE_CHUNK_DATA, TYPE_MANIFEST, TYPE_ACK,
        )
        from crypto.handshake import perform_handshake_initiator, perform_handshake_responder
        from crypto.crypto import encrypt, decrypt, compute_hmac, verify_hmac
        from crypto.identity import get_my_identity


def _send_encrypted_chunk(sock, session, my_id: str, payload: dict):
    """
    Chiffre un payload dict avec AES-256-GCM + HMAC et l'envoie via TYPE_CHUNK_DATA.
    Format identique à send_encrypted_payload de crypto.messaging.
    """
    raw        = json.dumps(payload).encode("utf-8")
    nonce, ct  = encrypt(session.session_key, raw)
    mac        = compute_hmac(session.session_key, nonce + ct)
    sock.sendall(build_json_packet(TYPE_CHUNK_DATA, my_id, {
        "nonce":      nonce.hex(),
        "ciphertext": ct.hex(),
        "hmac":       mac.hex(),
    }))


def _recv_encrypted_chunk(sock, session) -> dict | None:
    """
    Reçoit et déchiffre un paquet TYPE_CHUNK_DATA.
    Format identique à receive_encrypted_message de crypto.messaging.
    Retourne le dict déchiffré ou None si erreur.
    """
    try:
        msg_type, _, payload_bytes, _ = parse_packet_stream(sock)
        payload = parse_json_payload(payload_bytes)

        if msg_type != TYPE_CHUNK_DATA:
            print(f"[TRANSFER] ⚠️ Type inattendu : 0x{msg_type:02X}")
            return None

        nonce      = bytes.fromhex(payload["nonce"])
        ciphertext = bytes.fromhex(payload["ciphertext"])
        mac        = bytes.fromhex(payload["hmac"])

        if not verify_hmac(session.session_key, nonce + ciphertext, mac):
            print("[TRANSFER] 🚨 HMAC invalide — chunk rejeté")
            return None

        raw = decrypt(session.session_key, nonce, ciphertext)
        return json.loads(raw.decode("utf-8"))

    except Exception as e:
        print(f"[TRANSFER] ❌ Erreur réception chunk chiffré : {e}")
        return None


# ── Serveur de fichiers (côté émetteur) ──────────────────────────

def handle_transfer_server(sock: socket.socket, session, storage: LocalStorage, node_id: str):
    """
    Côté ÉMETTEUR — répond aux CHUNK_REQ avec les données chiffrées.
    Appelé depuis tcp_server.py après le handshake.
    """
    print(f"[TRANSFER] 📤 Session émetteur démarrée")

    try:
        while True:
            msg_type, _, payload_bytes, _ = parse_packet_stream(sock)
            payload = parse_json_payload(payload_bytes)

            # ── Réception d'une demande de chunk ─────────────────
            if msg_type == TYPE_CHUNK_REQ:
                file_id   = payload.get("file_id")
                chunk_idx = payload.get("chunk_idx")

                if not storage.has_chunk(file_id, chunk_idx):
                    sock.sendall(build_json_packet(TYPE_ACK, node_id, {
                        "file_id":   file_id,
                        "chunk_idx": chunk_idx,
                        "status":    "not_found",
                    }))
                    continue

                chunk_data = storage.get_chunk_data(file_id, chunk_idx)
                chunk_hash = hash_data(chunk_data)

                _send_encrypted_chunk(sock, session, node_id, {
                    "file_id":    file_id,
                    "chunk_idx":  chunk_idx,
                    "chunk_hash": chunk_hash,
                    "data":       base64.b64encode(chunk_data).decode(),
                })
                print(f"[TRANSFER] 📤 Chunk {chunk_idx} → {len(chunk_data)} bytes")

            # ── Manifest reçu — le pair veut télécharger un fichier
            elif msg_type == TYPE_MANIFEST:
                file_id = payload.get("file_id")
                print(f"[TRANSFER] 📋 Manifest reçu pour {payload.get('filename')} ({payload.get('nb_chunks')} chunks)")
                # On continue à écouter les CHUNK_REQ

            # ── Fin de transfert ──────────────────────────────────
            elif msg_type == TYPE_ACK:
                if payload.get("status") == "done":
                    print(f"[TRANSFER] ✅ Transfert terminé côté émetteur")
                    break

    except ConnectionError:
        pass
    except Exception as e:
        print(f"[TRANSFER] ❌ Erreur serveur transfert : {e}")


# ── Client de téléchargement (côté récepteur) ────────────────────

class TransferManager:
    """Gère les téléchargements de fichiers depuis les pairs."""

    def __init__(self, storage: LocalStorage):
        self.storage          = storage
        self.active_downloads = {}

    def fetch_file(
        self,
        manifest: dict,
        peer_ip: str,
        peer_port: int,
        on_complete=None,
    ):
        """
        Démarre le téléchargement d'un fichier depuis un pair.
        Connexion TCP séparée avec handshake + chiffrement AES-256-GCM.
        """
        file_id = manifest["file_id"]

        if file_id not in self.storage.files:
            self.storage.init_download(manifest)

        def download_thread():
            my_signing_key, my_id = get_my_identity()
            nb_chunks  = manifest["nb_chunks"]
            start_time = time.time()

            print(f"\n[TRANSFER] ⬇️  {manifest['filename']}")
            print(f"[TRANSFER]    {nb_chunks} chunks × {CHUNK_SIZE // 1024} KB")
            print(f"[TRANSFER]    Taille : {manifest['size'] / (1024*1024):.1f} MB\n")

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                sock.connect((peer_ip, peer_port))

                # Handshake chiffré
                session = perform_handshake_initiator(sock, my_id, my_signing_key)

                # Envoie le manifest pour identifier le fichier voulu
                sock.sendall(build_json_packet(TYPE_MANIFEST, my_id, manifest))

                # Chunks à télécharger
                chunks_todo = [
                    i for i in range(nb_chunks)
                    if not self.storage.has_chunk(file_id, i)
                ]
                print(f"[TRANSFER]    {len(chunks_todo)} chunks manquants")

                for chunk_idx in chunks_todo:
                    # Demande le chunk
                    sock.sendall(build_json_packet(TYPE_CHUNK_REQ, my_id, {
                        "file_id":   file_id,
                        "chunk_idx": chunk_idx,
                        "requester": my_id,
                    }))

                    # Reçoit et déchiffre
                    inner = _recv_encrypted_chunk(sock, session)
                    if not inner:
                        print(f"[TRANSFER] ⚠️ Chunk {chunk_idx} — réponse invalide")
                        continue

                    chunk_data = base64.b64decode(inner["data"])
                    done = self.storage.write_chunk(file_id, chunk_idx, chunk_data)

                    if done:
                        elapsed = time.time() - start_time
                        speed   = manifest["size"] / elapsed / (1024 * 1024)
                        print(f"\n[TRANSFER] 🎉 {manifest['filename']} reçu en {elapsed:.1f}s ({speed:.1f} MB/s)")
                        if on_complete:
                            on_complete(manifest["filename"])
                        break

                # Signale la fin
                sock.sendall(build_json_packet(TYPE_ACK, my_id, {
                    "file_id": file_id,
                    "status":  "done",
                }))
                sock.close()

            except Exception as e:
                print(f"[TRANSFER] ❌ Échec : {e}")
            finally:
                self.active_downloads.pop(file_id, None)

        t = threading.Thread(target=download_thread, daemon=True)
        self.active_downloads[file_id] = t
        t.start()
        return t

    def share_file(self, filepath: str, sender_id: str, signing_key=None) -> dict:
        """Indexe un fichier local pour le partage. Retourne le manifest."""
        from transfer.chunking import build_manifest
        manifest = build_manifest(filepath, sender_id, signing_key)
        self.storage.add_local_file(filepath, manifest)
        print(f"[TRANSFER] 🟢 Partagé : {manifest['filename']} ({manifest['nb_chunks']} chunks | ID: {manifest['file_id'][:16]}…)")
        return manifest


# ── Test standalone ───────────────────────────────────────────────

if __name__ == "__main__":
    import os, tempfile

    print("\n📦 Test Module 3.2 — Transfer Manager\n")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(os.urandom(1_500_000))
        tmp_path = f.name

    storage_sender = LocalStorage(".archipel_test_sender/index.json")
    manager_sender = TransferManager(storage_sender)

    _, my_id = get_my_identity()
    manifest = manager_sender.share_file(tmp_path, my_id)

    assert manifest["nb_chunks"] == 3
    assert manifest["size"]      == 1_500_000
    print(f"\n  ✅ Manifest : {manifest['nb_chunks']} chunks")
    print(f"  ✅ File ID  : {manifest['file_id'][:16]}…")
    print(f"  ✅ Import network.packet OK")
    print(f"\n✅ Tests Module 3.2 passent !\n")

    os.unlink(tmp_path)