"""
Archipel — Module 3.1 : Chunking
Sépare un fichier en blocs de 512KB, calcule les hashs, gère l'index local.
"""

import os
import json
import hashlib
from pathlib import Path

CHUNK_SIZE = 512 * 1024  # 512 KB


def hash_data(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(filepath: str, sender_id: str, my_signing_key=None) -> dict:
    """Génère le manifest d'un fichier local."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Fichier introuvable : {filepath}")

    file_size = os.path.getsize(filepath)
    file_id   = hash_file(filepath)
    filename  = os.path.basename(filepath)

    chunks = []
    with open(filepath, "rb") as f:
        idx = 0
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            chunks.append({
                "index": idx,
                "hash":  hash_data(data),
                "size":  len(data),
            })
            idx += 1

    manifest = {
        "file_id":    file_id,
        "filename":   filename,
        "size":       file_size,
        "chunk_size": CHUNK_SIZE,
        "nb_chunks":  len(chunks),
        "chunks":     chunks,
        "sender_id":  sender_id,
    }

    # Signature optionnelle sur le hash du manifest
    manifest_hash = hash_data(json.dumps(manifest, sort_keys=True).encode("utf-8"))
    if my_signing_key:
        try:
            manifest["signature"] = my_signing_key.sign(manifest_hash.encode()).signature.hex()
        except Exception:
            manifest["signature"] = ""
    else:
        manifest["signature"] = ""

    return manifest


def read_chunk(filepath: str, chunk_idx: int) -> bytes:
    """Lit un chunk spécifique depuis un fichier."""
    with open(filepath, "rb") as f:
        f.seek(chunk_idx * CHUNK_SIZE)
        return f.read(CHUNK_SIZE)


class LocalStorage:
    """Index local des fichiers partagés et téléchargements en cours."""

    def __init__(self, index_path: str = ".archipel/index.json"):
        self.index_path = index_path
        self.files      = {}  # file_id → {filepath, manifest, chunks_have}
        self._load()

    def _load(self):
        os.makedirs(os.path.dirname(self.index_path), exist_ok=True)
        try:
            if os.path.exists(self.index_path):
                with open(self.index_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.files = data.get("files", {})
        except Exception as e:
            print(f"[STORAGE] Erreur chargement : {e}")
            self.files = {}

    def _save(self):
        os.makedirs(os.path.dirname(self.index_path), exist_ok=True)
        try:
            with open(self.index_path, "w", encoding="utf-8") as f:
                json.dump({"files": self.files}, f, indent=2)
        except Exception as e:
            print(f"[STORAGE] Erreur sauvegarde : {e}")

    def add_local_file(self, filepath: str, manifest: dict):
        """Déclare un fichier complet local disponible au partage."""
        file_id = manifest["file_id"]
        self.files[file_id] = {
            "filepath":    filepath,
            "manifest":    manifest,
            "chunks_have": list(range(manifest["nb_chunks"])),
        }
        self._save()
        print(f"[STORAGE] 📁 Fichier indexé : {manifest['filename']} ({manifest['nb_chunks']} chunks)")

    def has_chunk(self, file_id: str, chunk_idx: int) -> bool:
        if file_id in self.files:
            return chunk_idx in self.files[file_id]["chunks_have"]
        return False

    def get_chunk_data(self, file_id: str, chunk_idx: int) -> bytes | None:
        if not self.has_chunk(file_id, chunk_idx):
            return None
        return read_chunk(self.files[file_id]["filepath"], chunk_idx)

    def init_download(self, manifest: dict, out_dir: str = "downloads"):
        """Initialise un téléchargement — crée le fichier de destination."""
        file_id = manifest["file_id"]
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, manifest["filename"])

        # Crée un fichier vide de la bonne taille
        with open(out_path, "wb") as f:
            f.truncate(manifest["size"])

        self.files[file_id] = {
            "filepath":    out_path,
            "manifest":    manifest,
            "chunks_have": [],
        }
        self._save()
        print(f"[STORAGE] ⬇️  Téléchargement initialisé : {manifest['filename']}")
        return out_path

    def write_chunk(self, file_id: str, chunk_idx: int, data: bytes) -> bool:
        """
        Écrit un chunk téléchargé après vérification du hash.
        Retourne True si le fichier est complet.
        """
        if file_id not in self.files:
            return False

        f_info = self.files[file_id]

        if chunk_idx in f_info["chunks_have"]:
            return False  # Déjà reçu

        # Vérification hash SHA-256
        expected_hash = next(
            (c["hash"] for c in f_info["manifest"]["chunks"] if c["index"] == chunk_idx),
            None
        )
        if expected_hash and hash_data(data) != expected_hash:
            print(f"[STORAGE] ⚠️ Hash invalide pour chunk {chunk_idx} — rejeté")
            return False

        # Écriture à la bonne position
        with open(f_info["filepath"], "r+b") as f:
            f.seek(chunk_idx * CHUNK_SIZE)
            f.write(data)

        f_info["chunks_have"].append(chunk_idx)
        self._save()

        nb_have  = len(f_info["chunks_have"])
        nb_total = f_info["manifest"]["nb_chunks"]
        print(f"[STORAGE] ✅ Chunk {chunk_idx+1}/{nb_total} reçu ({nb_have/nb_total*100:.0f}%)")

        # Fichier complet ?
        if nb_have == nb_total:
            self._verify_complete(file_id)
            return True
        return False

    def _verify_complete(self, file_id: str):
        """Vérifie le hash SHA-256 du fichier complet."""
        f_info   = self.files[file_id]
        filepath = f_info["filepath"]
        expected = f_info["manifest"]["file_id"]  # hash du fichier original
        actual   = hash_file(filepath)

        if actual == expected:
            print(f"[STORAGE] 🎉 Fichier complet et intègre : {f_info['manifest']['filename']}")
        else:
            print(f"[STORAGE] ❌ Hash fichier invalide — corruption détectée !")

    def progress(self, file_id: str) -> float:
        """Retourne le pourcentage de téléchargement (0.0 → 1.0)."""
        if file_id not in self.files:
            return 0.0
        f = self.files[file_id]
        return len(f["chunks_have"]) / f["manifest"]["nb_chunks"]


if __name__ == "__main__":
    import tempfile, os

    print("\n📦 Test Module 3.1 — Chunking\n")

    # Crée un fichier test de 2 MB
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(os.urandom(2 * 1024 * 1024))
        tmp_path = f.name

    manifest = build_manifest(tmp_path, sender_id="test_node")
    print(f"  ✅ Manifest généré : {manifest['nb_chunks']} chunks")
    print(f"  ✅ File ID : {manifest['file_id'][:16]}…")

    storage = LocalStorage(".archipel_test/index.json")
    storage.add_local_file(tmp_path, manifest)

    chunk = storage.get_chunk_data(manifest["file_id"], 0)
    assert chunk is not None
    assert hash_data(chunk) == manifest["chunks"][0]["hash"]
    print(f"  ✅ Lecture chunk 0 et vérification hash OK")

    os.unlink(tmp_path)
    print("\n✅ Tous les tests Module 3.1 passent !\n")