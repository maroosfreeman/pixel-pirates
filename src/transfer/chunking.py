"""
Archipel — Module 3.1 & 3.4 : Chunking
Sépare un fichier en blocs de 512KB, calcule les hashs, gère l'index local.
"""

import os
import hashlib
import json
from pathlib import Path

CHUNK_SIZE = 512 * 1024  # 512 KB

def hash_data(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def hash_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def build_manifest(filepath: str, sender_id: str, my_signing_key=None) -> dict:
    """Génère le dictionnaire Manifest pour un fichier local."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Fichier introuvable: {filepath}")

    file_size = os.path.getsize(filepath)
    file_id = hash_file(filepath)
    filename = os.path.basename(filepath)

    chunks = []
    with open(filepath, 'rb') as f:
        idx = 0
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            chunks.append({
                "index": idx,
                "hash": hash_data(data),
                "size": len(data)
            })
            idx += 1

    manifest = {
        "file_id": file_id,
        "filename": filename,
        "size": file_size,
        "chunk_size": CHUNK_SIZE,
        "nb_chunks": len(chunks),
        "chunks": chunks,
        "sender_id": sender_id,
    }

    # Signature sur le hash du manifest sans la signature elle-même
    manifest_str = json.dumps(manifest, sort_keys=True)
    manifest_hash = hash_data(manifest_str.encode("utf-8"))
    
    if my_signing_key:
        manifest["signature"] = my_signing_key.sign(manifest_hash.encode("utf-8")).signature.hex()
    else:
        manifest["signature"] = ""

    return manifest

def read_chunk(filepath: str, chunk_idx: int) -> bytes:
    """Lit un chunk spécifique depuis un fichier."""
    with open(filepath, 'rb') as f:
        f.seek(chunk_idx * CHUNK_SIZE)
        return f.read(CHUNK_SIZE)

class LocalStorage:
    def __init__(self, index_path=".archipel/index.db"):
        self.index_path = index_path
        self.files = {} # file_id -> {"filepath": str, "manifest": dict, "chunks_have": list/set}
        self.downloads = {} # file_id -> temporary download data
        self._load()

    def _load(self):
        try:
            os.makedirs(os.path.dirname(self.index_path), exist_ok=True)
            if os.path.exists(self.index_path):
                with open(self.index_path, 'r', encoding="utf-8") as f:
                    data = json.load(f)
                    self.files = data.get("files", {})
        except Exception as e:
            print(f"[STORAGE] Erreur _load: {e}")
            self.files = {}

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.index_path), exist_ok=True)
            with open(self.index_path, 'w', encoding="utf-8") as f:
                json.dump({"files": self.files}, f, indent=2)
        except Exception as e:
            print(f"[STORAGE] Erreur _save: {e}")

    def add_local_file(self, filepath: str, manifest: dict):
        """Déclare un fichier complet local pour le partage."""
        file_id = manifest["file_id"]
        self.files[file_id] = {
            "filepath": filepath,
            "manifest": manifest,
            "chunks_have": list(range(manifest["nb_chunks"]))
        }
        self._save()

    def has_chunk(self, file_id: str, chunk_idx: int) -> bool:
        if file_id in self.files:
            return chunk_idx in self.files[file_id]["chunks_have"]
        return False

    def get_chunk_data(self, file_id: str, chunk_idx: int) -> bytes:
        if not self.has_chunk(file_id, chunk_idx):
            return None
        filepath = self.files[file_id]["filepath"]
        return read_chunk(filepath, chunk_idx)
    
    def init_download(self, manifest: dict, out_dir="downloads"):
        file_id = manifest["file_id"]
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, manifest["filename"])
        
        # Crée un fichier de la bonne taille rempli de 0s
        with open(out_path, "wb") as f:
            f.truncate(manifest["size"])
            
        self.files[file_id] = {
            "filepath": out_path,
            "manifest": manifest,
            "chunks_have": []
        }
        self._save()
        
    def write_down_chunk(self, file_id: str, chunk_idx: int, data: bytes) -> bool:
        """Écrit un chunk téléchargé, retourne True si complet."""
        if file_id not in self.files:
            return False
            
        f_info = self.files[file_id]
        if chunk_idx in f_info["chunks_have"]:
            return False # Déjà là
            
        # Verify hash
        expected_hash = None
        for c in f_info["manifest"]["chunks"]:
            if c["index"] == chunk_idx:
                expected_hash = c["hash"]
                break
                
        if expected_hash and hash_data(data) != expected_hash:
            print(f"[STORAGE] ⚠️ Hash mismatch pour chunk {chunk_idx}")
            return False
            
        filepath = f_info["filepath"]
        with open(filepath, "r+b") as f:
            f.seek(chunk_idx * CHUNK_SIZE)
            f.write(data)
            
        f_info["chunks_have"].append(chunk_idx)
        self._save()
        
        # Est-il complet ?
        return len(f_info["chunks_have"]) == f_info["manifest"]["nb_chunks"]

