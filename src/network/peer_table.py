"""
Archipel — Module 1.2 : Peer Table
Table de routage des pairs connus sur le réseau.
"""

import time
import json
import os
import tempfile
from pathlib import Path

PEER_FILE = ".archipel/index.db"

class PeerTable:
    def __init__(self, file_path=PEER_FILE):
        self.file_path = file_path
        self.peers = {}
        self._load()

    def _load(self):
        try:
            os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
            if os.path.exists(self.file_path):
                with open(self.file_path, "r", encoding="utf-8") as f:
                    self.peers = json.load(f)
        except Exception as e:
            print(f"[PeerTable] Erreur chargement: {e}")
            self.peers = {}

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
            with tempfile.NamedTemporaryFile("w", delete=False, dir=os.path.dirname(self.file_path), encoding="utf-8") as f:
                json.dump(self.peers, f, indent=2)
                tmp_name = f.name
            os.replace(tmp_name, self.file_path)
        except Exception as e:
            print(f"[PeerTable] Erreur sauvegarde: {e}")

    def update_peer(self, node_id: str, ip: str, port):
        """Ajoute ou met à jour un pair dans la table."""
        is_new = node_id not in self.peers
        self.peers[node_id] = {
            'ip': ip,
            'tcp_port': int(port),      # ← converti en int
            'last_seen': time.time(),
            'shared_files': [],          # ← conforme au sujet
            'reputation': self.peers.get(node_id, {}).get('reputation', 1.0),
        }
        if is_new:
            print(f"🆕 Nouveau pair détecté : {node_id[:10]}… @ {ip}:{port}")
        self._save()

    def clean_old_peers(self):
        """Supprime les pairs sans HELLO depuis plus de 90 secondes."""
        now = time.time()
        to_delete = [
            uid for uid, info in self.peers.items()
            if now - info['last_seen'] > 90
        ]
        for uid in to_delete:
            print(f"❌ Pair déconnecté (timeout 90s) : {uid[:10]}…")
            del self.peers[uid]
        if to_delete:
            self._save()

    def update_reputation(self, node_id: str, success: bool):
        """Met à jour le score de réputation d'un pair."""
        if node_id in self.peers:
            old = self.peers[node_id]['reputation']
            self.peers[node_id]['reputation'] = old * 0.8 + (1.0 if success else 0.0) * 0.2
            self._save()

    def display(self):
        """Affiche la table des pairs dans le terminal."""
        print("\n--- ARCHIPEL PEER TABLE ---")
        if not self.peers:
            print("  (Aucun pair détecté)")
        else:
            for uid, info in self.peers.items():
                age = int(time.time() - info['last_seen'])
                print(
                    f"  ID: {uid[:10]}… | "
                    f"IP: {info['ip']} | "
                    f"Port: {info['tcp_port']} | "
                    f"Vu il y a: {age}s | "
                    f"Réputation: {info['reputation']:.2f}"
                )
        print("---------------------------\n")

    def get_alive(self) -> list:
        """Retourne uniquement les pairs encore actifs."""
        now = time.time()
        return [
            info for info in self.peers.values()
            if now - info['last_seen'] <= 90
        ]