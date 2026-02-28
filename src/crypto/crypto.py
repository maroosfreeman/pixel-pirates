"""
Archipel — Module 2.1 : Cryptographie
X25519 (échange de clé) + AES-256-GCM (chiffrement) + HKDF-SHA256 (dérivation)
"""

import os
import hmac
import hashlib

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
    print("[CRYPTO] ⚠️ 'cryptography' absent — pip install cryptography")


def generate_ephemeral_keypair() -> tuple:
    """Génère une paire X25519 éphémère. Retourne (private_key, public_key_bytes)."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography non installé")
    private_key      = X25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_key, public_key_bytes


def compute_shared_secret(private_key, peer_public_key_bytes: bytes) -> bytes:
    """Calcule le secret partagé Diffie-Hellman X25519."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography non installé")
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    return private_key.exchange(peer_public_key)


def derive_session_key(shared_secret: bytes, salt: bytes = None, info: bytes = b"archipel-session-v1") -> bytes:
    """Dérive une clé AES-256 (32 bytes) via HKDF-SHA256."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography non installé")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(shared_secret)


def encrypt(session_key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple:
    """Chiffre avec AES-256-GCM. Retourne (nonce, ciphertext)."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography non installé")
    nonce  = os.urandom(12)
    aesgcm = AESGCM(session_key)
    return nonce, aesgcm.encrypt(nonce, plaintext, associated_data)


def decrypt(session_key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
    """Déchiffre AES-256-GCM."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography non installé")
    return AESGCM(session_key).decrypt(nonce, ciphertext, associated_data)


def compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(compute_hmac(key, data), expected)


if __name__ == "__main__":
    print("\n🔐 Test Module 2.1 — Cryptographie Archipel\n")
    priv_a, pub_a = generate_ephemeral_keypair()
    priv_b, pub_b = generate_ephemeral_keypair()
    secret_a = compute_shared_secret(priv_a, pub_b)
    secret_b = compute_shared_secret(priv_b, pub_a)
    assert secret_a == secret_b
    print("  ✅ Secret partagé X25519 identique des deux côtés")
    session_key = derive_session_key(secret_a)
    print(f"  ✅ Clé de session HKDF-SHA256 : {session_key.hex()[:16]}…")
    message = b"Salut Archipel !"
    nonce, ct = encrypt(session_key, message)
    assert decrypt(session_key, nonce, ct) == message
    print("  ✅ Chiffrement AES-256-GCM OK")
    key = os.urandom(32)
    mac = compute_hmac(key, b"test")
    assert verify_hmac(key, b"test", mac)
    print("  ✅ HMAC-SHA256 OK")
    print("\n✅ Tous les tests Module 2.1 passent !\n")
