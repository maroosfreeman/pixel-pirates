"""
Archipel — Module 3.2 & 3.3 : Transfer Manager & Download Pipeline
A gère le rapatriement des chunks via CHUNK_REQ / CHUNK_DATA.
"""

import time
import base64
import threading
from transfer.chunking import LocalStorage

class TransferManager:
    def __init__(self, storage: LocalStorage, tcp_server):
        self.storage = storage
        self.tcp_server = tcp_server  # reference to easily send packets
        self.active_downloads = {}

    def fetch_file(self, manifest: dict, peer_id: str, peer_ip: str, peer_port: int, on_complete=None):
        """
        Démarre un téléchargement de fichier (stratégie pipeline basique).
        Dans un projet complet: Rarest First multiprocessing.
        Ici pour la démo: On télécharge séquentiellement ou avec un simple Thread.
        """
        file_id = manifest["file_id"]
        
        if file_id not in self.storage.files:
            self.storage.init_download(manifest)

        def download_thread():
            import socket
            from network.packet import build_json_packet, TYPE_CHUNK_REQ, TYPE_CHUNK_DATA, parse_packet_stream, parse_json_payload
            from crypto.handshake import perform_handshake_initiator
            from crypto.identity import get_my_identity

            my_signing_key, my_id = get_my_identity()

            print(f"[TRANSFER] Démarrage téléchargement {manifest['filename']} ({manifest['nb_chunks']} chunks)")

            try:
                # Etablit connexion vers le pair pour transfer data
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((peer_ip, peer_port))
                
                # Handshake
                session = perform_handshake_initiator(sock, my_id, my_signing_key)
                
                # Download loop (sérialisé pour simuler le pipeline)
                for chunk_idx in range(manifest["nb_chunks"]):
                    if self.storage.has_chunk(file_id, chunk_idx):
                        continue
                        
                    # Send CHUNK_REQ
                    req = {
                        "file_id": file_id,
                        "chunk_idx": chunk_idx,
                        "requester": my_id
                    }
                    sock.sendall(build_json_packet(TYPE_CHUNK_REQ, my_id, req))
                    
                    # Receive CHUNK_DATA
                    # Important: these messages are sent as clear JSON payload right after handshake.
                    # As specs say "chiffré avec session key", we could wrap them into TYPE_MSG, 
                    # OR we encrypt the JSON body manually. For simplicity we will encrypt the JSON and pack it in CHUNK_DATA.
                    msg_type, _, payload_bytes, _ = parse_packet_stream(sock)
                    if msg_type == TYPE_CHUNK_DATA:
                        from crypto.crypto import decrypt
                        decrypted_payload = decrypt(session.session_key, payload_bytes[:12], payload_bytes[12:])
                        resp = json.loads(decrypted_payload.decode("utf-8"))
                        
                        chunk_data = base64.b64decode(resp["data"])
                        chunk_hash = resp["chunk_hash"]
                        
                        done = self.storage.write_down_chunk(file_id, chunk_idx, chunk_data)
                        print(f"  [TRANSFER] Chunk {chunk_idx}/{manifest['nb_chunks']} téléchargé.")
                        if done:
                            print(f"[TRANSFER] ✅ Téléchargement terminé pour {manifest['filename']} !")
                            if on_complete:
                                on_complete(manifest['filename'])
                sock.close()
            except Exception as e:
                print(f"[TRANSFER] ❌ Echec téléchargement: {e}")

        t = threading.Thread(target=download_thread, daemon=True)
        self.active_downloads[file_id] = t
        t.start()
