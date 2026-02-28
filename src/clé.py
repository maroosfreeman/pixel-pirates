"""
Archipel — Générateur de clés PKI Ed25519
==========================================
Génère une paire de clés Ed25519 pour un nœud Archipel.

Usage :
    python src/clé.py
    python src/clé.py --name mon_noeud
    python src/clé.py --output ./mes_cles/
"""

import os
import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime
import sys
import tempfile


def generate_keys_pynacl():
    """Génère avec PyNaCl (libsodium) — recommandé en production."""
    # Imports optionnels — silence Pylance si non installés
    import nacl.signing  # type: ignore[reportMissingImports]
    import nacl.encoding  # type: ignore[reportMissingImports]

    # Génère la paire de clés Ed25519
    signing_key = nacl.signing.SigningKey.generate()
    verify_key  = signing_key.verify_key

    private_bytes = bytes(signing_key)           # 32 bytes — seed privée
    public_bytes  = bytes(verify_key)            # 32 bytes — clé publique

    return private_bytes, public_bytes


def generate_keys_cryptography():
    """Génère avec la lib `cryptography` — alternative si PyNaCl absent."""
    # Import optionnel — silence Pylance si non installé
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore[reportMissingImports]

    private_key   = Ed25519PrivateKey.generate()
    public_key    = private_key.public_key()

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption  # type: ignore[reportMissingImports]
    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes  = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    return private_bytes, public_bytes


def generate_keys_fallback():
    """Fallback sans dépendance — pour tests uniquement, NON sécurisé."""
    import secrets
    print("  ATTENTION : fallback sans crypto réelle — installez PyNaCl !")
    private_bytes = secrets.token_bytes(32)
    public_bytes  = hashlib.sha256(private_bytes).digest()
    return private_bytes, public_bytes


def generate_pki_keys():
    """
    Essaie les bibliothèques dans l'ordre de préférence.
    Retourne (private_bytes, public_bytes, lib_used).
    """
    # Essai 1 : PyNaCl (recommandé)
    try:
        private_bytes, public_bytes = generate_keys_pynacl()
        return private_bytes, public_bytes, "PyNaCl (libsodium)"
    except ImportError:
        pass
    except Exception as e:
        print(f"  PyNaCl présent mais échec de génération : {e}")

    # Essai 2 : cryptography
    try:
        private_bytes, public_bytes = generate_keys_cryptography()
        return private_bytes, public_bytes, "cryptography (hazmat)"
    except ImportError:
        pass
    except Exception as e:
        print(f"  cryptography présent mais échec de génération : {e}")

    # Fallback
    private_bytes, public_bytes = generate_keys_fallback()
    return private_bytes, public_bytes, "fallback (NON sécurisé)"


def save_keys(private_bytes, public_bytes, output_dir: str = ".archipel", name: str = "node"):
    """
    Sauvegarde les clés sur disque.

    Fichiers générés :
    - identity.json       → clé privée (chmod 600, JAMAIS dans git)
    - identity_public.json → clé publique (partageable)
    """
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    # Validations basiques des octets de clé
    if not isinstance(private_bytes, (bytes, bytearray)):
        raise TypeError("private_bytes must be bytes")
    if not isinstance(public_bytes, (bytes, bytearray)):
        raise TypeError("public_bytes must be bytes")
    if len(public_bytes) != 32:
        raise ValueError(f"public_bytes must be 32 bytes (got {len(public_bytes)})")
    if len(private_bytes) < 32:
        raise ValueError(f"private_bytes must be at least 32 bytes (got {len(private_bytes)})")

    node_id     = public_bytes.hex()
    fingerprint = hashlib.sha256(public_bytes).hexdigest()[:16]
    created_at  = datetime.now().isoformat()

    # ── Fichier PUBLIC (partageable) ──────────────────────────────
    public_data = {
        "node_name":   name,
        "node_id":     node_id,
        "public_key":  public_bytes.hex(),
        "fingerprint": fingerprint,
        "algorithm":   "Ed25519",
        "created_at":  created_at,
    }

    public_path = output / "identity_public.json"
    # Écriture atomique pour éviter les fichiers corrompus
    try:
        with tempfile.NamedTemporaryFile('w', delete=False, dir=str(output), encoding='utf-8') as tf:
            json.dump(public_data, tf, indent=2, ensure_ascii=False)
            tmp_public = Path(tf.name)
        os.replace(tmp_public, public_path)
    except Exception as e:
        raise RuntimeError(f"Impossible d'écrire la clé publique: {e}")

    # ── Fichier PRIVÉ (confidentiel) ──────────────────────────────
    private_data = {
        **public_data,
        "private_key_seed": private_bytes.hex(),
        "WARNING": "NE JAMAIS partager ce fichier. NE JAMAIS le mettre dans git.",
    }

    private_path = output / "identity.json"
    try:
        with tempfile.NamedTemporaryFile('w', delete=False, dir=str(output), encoding='utf-8') as tf:
            json.dump(private_data, tf, indent=2, ensure_ascii=False)
            tmp_private = Path(tf.name)
        os.replace(tmp_private, private_path)
    except Exception as e:
        raise RuntimeError(f"Impossible d'écrire la clé privée: {e}")

    # Permissions restrictives (lecture seule propriétaire)
    try:
        # Tentative de restreindre les permissions (best-effort)
        os.chmod(private_path, 0o600)
    except Exception:
        # Sur Windows, chmod est souvent inefficace; on continue sans échouer
        pass

    return public_path, private_path, fingerprint, node_id


def main():
    parser = argparse.ArgumentParser(
        description="Archipel — Générateur de clés PKI Ed25519"
    )
    parser.add_argument(
        "--name",
        default="node",
        help="Nom du nœud (ex: alice, bob, node1)"
    )
    parser.add_argument(
        "--output",
        default=".archipel",
        help="Dossier de sortie (défaut: .archipel/)"
    )
    args = parser.parse_args()

    print("\n╔══════════════════════════════════════════╗")
    print("║   Archipel — Génération de clés PKI   ║")
    print("╚══════════════════════════════════════════╝\n")

    try:
        # Génération
        print("  Génération de la paire de clés Ed25519...")
        private_bytes, public_bytes, lib_used = generate_pki_keys()
        print(f"  Bibliothèque utilisée : {lib_used}")

        # Sauvegarde
        public_path, private_path, fingerprint, node_id = save_keys(
            private_bytes, public_bytes,
            output_dir=args.output,
            name=args.name,
        )
    except KeyboardInterrupt:
        print("\nInterrompu par l'utilisateur.")
        sys.exit(2)
    except Exception as e:
        print(f"Erreur: {e}")
        sys.exit(1)

    # Affichage
    print(f"""
  Clés générées avec succès !

  ┌─────────────────────────────────────────────┐
  │  Nœud          : {args.name:<28}│
  │  Fingerprint   : {fingerprint:<28}│
  │  Node ID       : {node_id[:32]:<32}│
  │                  {node_id[32:64]:<32}│
  └─────────────────────────────────────────────┘

  Clé publique  → {public_path}
  Clé privée   → {private_path}  (chmod 600)

  Ne jamais partager identity.json
  Ajouter {args.output}/ dans votre .gitignore
""")

    # Vérifie que .gitignore protège bien le dossier
    gitignore = Path(".gitignore")
    if gitignore.exists():
        content = gitignore.read_text()
        out_entry = str(Path(args.output).as_posix()).rstrip('/')
        if out_entry not in content and (out_entry + '/') not in content:
            print(f"   ATTENTION : {out_entry}/ n'est pas dans votre .gitignore !")
            print(f"      Ajoutez cette ligne : {out_entry}/\n")
        else:
            print(f"  .gitignore protège bien le dossier {out_entry}/\n")


if __name__ == "__main__":
    main()