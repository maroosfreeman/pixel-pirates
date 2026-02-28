"""
Archipel — Module 2.3 : Web of Trust (Authentification sans CA)
Modèle TOFU (Trust On First Use) inspiré de PGP, simplifié pour le hackathon.

- Premier contact : clé publique stockée localement avec empreinte
- Reconnexion     : vérification que la clé correspond (détection MITM)
- Révocation      : broadcast signé de révocation de clé
- Propagation     : un nœud peut signer la clé d'un autre pair
"""

import json
import os
import hashlib
import time
import sys
from pathlib import Path

TRUST_STORE_PATH = ".archipel/trust_store.json"


class TrustStore:
    """
    Stocke et gère les clés publiques des pairs connus.
    Modèle TOFU — premier contact = confiance automatique.
    """

    def __init__(self, path: str = TRUST_STORE_PATH):
        self.path  = path
        self._store = {}
        self._load()

    def _load(self):
        """Charge le trust store depuis le disque."""
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        try:
            with open(self.path) as f:
                self._store = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._store = {}

    def _save(self):
        """Sauvegarde le trust store sur le disque."""
        with open(self.path, "w") as f:
            json.dump(self._store, f, indent=2)

    def _fingerprint(self, public_key_hex: str) -> str:
        """Calcule l'empreinte SHA-256 d'une clé publique (16 chars)."""
        return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]

    # ── TOFU ─────────────────────────────────────────────────────

    def first_contact(self, node_id: str, public_key_hex: str) -> bool:
        """
        Premier contact avec un pair — TOFU.
        Retourne True si c'est vraiment le premier contact.
        """
        if node_id in self._store:
            return False  # Déjà connu

        self._store[node_id] = {
            "public_key":  public_key_hex,
            "fingerprint": self._fingerprint(public_key_hex),
            "first_seen":  time.time(),
            "last_seen":   time.time(),
            "trusted":     True,
            "revoked":     False,
            "signed_by":   [],  # Nœuds qui ont signé cette clé
        }
        self._save()
        print(f"[TRUST] 🆕 TOFU — Nouveau pair enregistré : {node_id[:16]}…")
        print(f"[TRUST]    Empreinte : {self._fingerprint(public_key_hex)}")
        return True

    def verify(self, node_id: str, public_key_hex: str) -> str:
        """
        Vérifie la clé publique d'un pair à la reconnexion.
        Retourne : 'ok' | 'new' | 'mismatch' | 'revoked'
        """
        if node_id not in self._store:
            self.first_contact(node_id, public_key_hex)
            return "new"

        entry = self._store[node_id]

        if entry.get("revoked"):
            print(f"[TRUST] 🚫 Pair révoqué : {node_id[:16]}…")
            return "revoked"

        if entry["public_key"] != public_key_hex:
            print(f"[TRUST] ⚠️  ALERTE MITM — Clé différente pour {node_id[:16]}…")
            print(f"[TRUST]    Attendue  : {entry['fingerprint']}")
            print(f"[TRUST]    Reçue     : {self._fingerprint(public_key_hex)}")
            return "mismatch"

        # Mise à jour du last_seen
        self._store[node_id]["last_seen"] = time.time()
        self._save()
        return "ok"

    # ── Révocation ────────────────────────────────────────────────

    def revoke(self, node_id: str, reason: str = "compromission"):
        """Révoque la clé d'un pair (ex: compromission signalée)."""
        if node_id in self._store:
            self._store[node_id]["revoked"] = True
            self._store[node_id]["revoke_reason"] = reason
            self._store[node_id]["revoke_time"]   = time.time()
            self._save()
            print(f"[TRUST] 🚫 Clé révoquée : {node_id[:16]}… ({reason})")

    def is_revoked(self, node_id: str) -> bool:
        """Vérifie si un pair est révoqué."""
        return self._store.get(node_id, {}).get("revoked", False)

    # ── Propagation de confiance ──────────────────────────────────

    def sign_peer(self, node_id: str, signer_node_id: str):
        """
        Un nœud signe la clé d'un autre pair pour l'introduire au réseau.
        Augmente le score de confiance.
        """
        if node_id in self._store:
            signers = self._store[node_id].get("signed_by", [])
            if signer_node_id not in signers:
                signers.append(signer_node_id)
                self._store[node_id]["signed_by"] = signers
                self._save()
                print(f"[TRUST] ✍️  {signer_node_id[:16]}… a signé la clé de {node_id[:16]}…")

    def trust_score(self, node_id: str) -> float:
        """
        Calcule le score de confiance d'un pair.
        0.5 = TOFU seul | +0.1 par signature | 1.0 max
        """
        entry = self._store.get(node_id, {})
        if not entry or entry.get("revoked"):
            return 0.0
        score = 0.5 + len(entry.get("signed_by", [])) * 0.1
        return min(score, 1.0)

    def display(self):
        """Affiche le trust store dans le terminal."""
        print("\n--- ARCHIPEL TRUST STORE ---")
        if not self._store:
            print("  (Aucun pair connu)")
        else:
            for node_id, entry in self._store.items():
                status = "🚫 RÉVOQUÉ" if entry.get("revoked") else "✅ Approuvé"
                score  = self.trust_score(node_id)
                print(
                    f"  {node_id[:16]}… | "
                    f"Empreinte: {entry['fingerprint']} | "
                    f"Confiance: {score:.1f} | "
                    f"{status}"
                )
        print("----------------------------\n")

    def get_all(self) -> dict:
        return dict(self._store)


# ── Test standalone ───────────────────────────────────────────────

if __name__ == "__main__":
    import shutil
    # Nettoyage pour test propre
    if os.path.exists(".archipel/trust_store.json"):
        os.remove(".archipel/trust_store.json")

    print("\n🔐 Test Module 2.3 — Web of Trust\n")

    store   = TrustStore()
    node_a  = "a" * 64
    node_b  = "b" * 64
    key_a   = "aa" * 32
    key_a2  = "bb" * 32  # Clé différente → MITM simulé

    # TOFU
    store.first_contact(node_a, key_a)
    assert store.verify(node_a, key_a) == "ok"
    print("  ✅ TOFU OK")

    # Détection MITM
    result = store.verify(node_a, key_a2)
    assert result == "mismatch"
    print("  ✅ Détection MITM OK")

    # Nouveau pair
    result = store.verify(node_b, key_a)
    assert result == "new"
    print("  ✅ Nouveau pair détecté OK")

    # Révocation
    store.revoke(node_a, "test")
    assert store.verify(node_a, key_a) == "revoked"
    print("  ✅ Révocation OK")

    # Propagation de confiance
    store.sign_peer(node_b, node_a)
    assert store.trust_score(node_b) > 0.5
    print(f"  ✅ Propagation de confiance OK (score: {store.trust_score(node_b):.1f})")

    store.display()
    print("✅ Tous les tests Module 2.3 passent !\n")
