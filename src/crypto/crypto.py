"""
Archipel — Module 2.1 : Cryptographie des nœuds
X25519 (échange de clé) + AES-256-GCM (chiffrement) + HKDF-SHA256 (dérivation)
Forward Secrecy : nouvelle clé de session à chaque connexion TCP
"""

import os
import hmac
import hashlib
import struct

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
    print("[CRYPTO] ⚠️ 'cryptography' absent — pip install cryptography")


# ── Clés éphémères X25519 ─────────────────────────────────────────

def generate_ephemeral_keypair() -> tuple:
    """
    Génère une paire de clés X25519 éphémère pour une session.
    Retourne (private_key, public_key_bytes).
    Nouvelle paire à chaque connexion TCP → Forward Secrecy.
    """
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography non installé")

    private_key      = X25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    return private_key, public_key_bytes


def compute_shared_secret(private_key, peer_public_key_bytes: bytes) -> bytes:
    """
    Calcule le secret partagé Diffie-Hellman X25519.
    private_key      : notre clé privée X25519 éphémère
    peer_public_key_bytes : clé publique X25519 du pair (32 bytes)
    Retourne le secret partagé brut (32 bytes).
    """
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography non installé")

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    return private_key.exchange(peer_public_key)


# ── Dérivation de clé HKDF-SHA256 ────────────────────────────────

def derive_session_key(shared_secret: bytes, salt: bytes = None, info: bytes = b"archipel-session-v1") -> bytes:
    """
    Dérive une clé de session AES-256 (32 bytes) depuis le secret partagé.
    Utilise HKDF-SHA256 — standard recommandé par le sujet.
    salt : nonce partagé entre les deux pairs (optionnel)
    info : contexte de dérivation (fixe par protocole)
    """
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography non installé")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


# ── Chiffrement AES-256-GCM ───────────────────────────────────────

def encrypt(session_key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple:
    """
    Chiffre un message avec AES-256-GCM.
    Retourne (nonce, ciphertext) — nonce aléatoire de 12 bytes.
    associated_data : données authentifiées mais non chiffrées (header du paquet).
    """
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography non installé")

    nonce  = os.urandom(12)  # 96 bits — recommandé pour AES-GCM
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt(session_key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
    """
    Déchiffre un message AES-256-GCM.
    Lève InvalidTag si le message est altéré ou la clé incorrecte.
    """
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography non installé")

    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


# ── HMAC-SHA256 (intégrité des paquets) ──────────────────────────

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Calcule un HMAC-SHA256 sur les données."""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected: bytes) -> bool:
    """Vérifie un HMAC-SHA256 de manière sécurisée (résistant aux timing attacks)."""
    actual = compute_hmac(key, data)
    return hmac.compare_digest(actual, expected)


# ── Test standalone ───────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🔐 Test Module 2.1 — Cryptographie Archipel\n")

    # 1. Génération des paires éphémères
    priv_a, pub_a = generate_ephemeral_keypair()
    priv_b, pub_b = generate_ephemeral_keypair()
    print(f"  ✅ Clés éphémères X25519 générées")
    print(f"     A pub : {pub_a.hex()[:16]}…")
    print(f"     B pub : {pub_b.hex()[:16]}…")

    # 2. Calcul du secret partagé (doit être identique des deux côtés)
    secret_a = compute_shared_secret(priv_a, pub_b)
    secret_b = compute_shared_secret(priv_b, pub_a)
    assert secret_a == secret_b, "❌ Secrets différents !"
    print(f"  ✅ Secret partagé X25519 identique des deux côtés")

    # 3. Dérivation de la clé de session
    session_key = derive_session_key(secret_a)
    print(f"  ✅ Clé de session dérivée via HKDF-SHA256 : {session_key.hex()[:16]}…")

    # 4. Chiffrement / déchiffrement
    message    = b"Salut Archipel depuis le Sprint 2 !"
    nonce, ct  = encrypt(session_key, message)
    plaintext  = decrypt(session_key, nonce, ct)
    assert plaintext == message, "❌ Déchiffrement échoué !"
    print(f"  ✅ Chiffrement AES-256-GCM OK")
    print(f"     Message  : {message.decode()}")
    print(f"     Chiffré  : {ct.hex()[:16]}… ({len(ct)} bytes)")

    # 5. HMAC
    key  = os.urandom(32)
    data = b"paquet archipel"
    mac  = compute_hmac(key, data)
    assert verify_hmac(key, data, mac)
    print(f"  ✅ HMAC-SHA256 OK")

    print("\n✅ Tous les tests Module 2.1 passent !\n")
