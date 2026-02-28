"""
Archipel — Module 2.4 : Chiffrement des messages
Chaque message est chiffré AES-256-GCM + authentifié HMAC-SHA256
Utilise la clé de session établie lors du handshake (Module 2.2)
"""

import json
import socket
import struct
import time
import sys
from pathlib import Path

# Imports flexibles
try:
    from crypto.crypto import encrypt, decrypt, compute_hmac, verify_hmac
    from crypto.handshake import (
        HandshakeSession,
        perform_handshake_initiator,
        perform_handshake_responder,
        encode_tlv,
        decode_tlv,
    )
    from crypto.trust_store import TrustStore
except ImportError:
    src_dir = str(Path(__file__).resolve().parents[1])
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    from crypto.crypto import encrypt, decrypt, compute_hmac, verify_hmac
    from crypto.handshake import (
        HandshakeSession,
        perform_handshake_initiator,
        perform_handshake_responder,
        encode_tlv,
        decode_tlv,
    )
    from crypto.trust_store import TrustStore

# Types TLV
TLV_MESSAGE  = 0x0010
TLV_PING     = 0x00F0
TLV_PONG     = 0x00F1


def send_encrypted_message(
    sock: socket.socket,
    session: HandshakeSession,
    my_node_id: str,
    text: str,
):
    """
    Envoie un message texte chiffré AES-256-GCM via TCP.
    Structure du payload chiffré :
      { "from": node_id, "text": text, "ts": timestamp }
    """
    plaintext = json.dumps({
        "from": my_node_id,
        "text": text,
        "ts":   time.time(),
    }).encode()

    # Chiffre avec la clé de session
    nonce, ciphertext = encrypt(session.session_key, plaintext)

    # HMAC sur (nonce + ciphertext) pour l'intégrité
    mac = compute_hmac(session.session_key, nonce + ciphertext)

    # Encode le payload chiffré en TLV
    payload = {
        "nonce":      nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "hmac":       mac.hex(),
    }
    msg = encode_tlv(TLV_MESSAGE, payload)
    sock.sendall(msg)
    print(f"[MSG] 📤 Message chiffré envoyé ({len(ciphertext)} bytes)")


def receive_encrypted_message(
    sock: socket.socket,
    session: HandshakeSession,
) -> dict | None:
    """
    Reçoit et déchiffre un message AES-256-GCM.
    Retourne le dict { from, text, ts } ou None si erreur.
    """
    try:
        msg_type, payload = decode_tlv(sock)
    except Exception as e:
        print(f"[MSG] ❌ Erreur réception : {e}")
        return None

    if msg_type == TLV_PING:
        # Répond au PING
        pong = encode_tlv(TLV_PONG, {"ts": time.time()})
        sock.sendall(pong)
        return None

    if msg_type != TLV_MESSAGE:
        print(f"[MSG] ❓ Type inattendu : 0x{msg_type:04X}")
        return None

    try:
        nonce      = bytes.fromhex(payload["nonce"])
        ciphertext = bytes.fromhex(payload["ciphertext"])
        mac        = bytes.fromhex(payload["hmac"])
    except (KeyError, ValueError) as e:
        print(f"[MSG] ❌ Payload malformé : {e}")
        return None

    # Vérifie le HMAC avant de déchiffrer
    if not verify_hmac(session.session_key, nonce + ciphertext, mac):
        print("[MSG] 🚨 HMAC invalide — message rejeté (altération détectée)")
        return None

    # Déchiffre
    try:
        plaintext = decrypt(session.session_key, nonce, ciphertext)
        data      = json.loads(plaintext.decode())
        print(f"[MSG] 📥 Message reçu de {data.get('from', '?')[:16]}… : {data.get('text', '')}")
        return data
    except Exception as e:
        print(f"[MSG] ❌ Déchiffrement échoué : {e}")
        return None


class SecureChannel:
    """
    Canal de communication chiffré entre deux nœuds.
    Combine handshake + chiffrement + trust store.
    """

    def __init__(self, my_node_id: str, trust_store: TrustStore = None):
        self.my_node_id  = my_node_id
        self.trust_store = trust_store or TrustStore()
        self.session: HandshakeSession = None

    def connect(self, host: str, port: int) -> bool:
        """
        Ouvre une connexion TCP chiffrée vers un pair.
        Effectue le handshake et vérifie la confiance TOFU.
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))

            # Handshake
            self.session = perform_handshake_initiator(self.sock, self.my_node_id)

            # Vérification TOFU
            result = self.trust_store.verify(
                self.session.peer_node_id,
                self.session.peer_public_x25519.hex(),
            )
            if result == "mismatch":
                print(f"[SECURE] 🚨 MITM détecté — connexion refusée !")
                self.sock.close()
                return False
            if result == "revoked":
                print(f"[SECURE] 🚫 Pair révoqué — connexion refusée !")
                self.sock.close()
                return False

            print(f"[SECURE] ✅ Canal sécurisé établi avec {self.session.peer_node_id[:16]}…")
            return True

        except Exception as e:
            print(f"[SECURE] ❌ Connexion échouée : {e}")
            return False

    def send(self, text: str):
        """Envoie un message chiffré."""
        if not self.session:
            raise RuntimeError("Pas de session active — appelez connect() d'abord")
        send_encrypted_message(self.sock, self.session, self.my_node_id, text)

    def receive(self) -> dict | None:
        """Reçoit et déchiffre un message."""
        if not self.session:
            raise RuntimeError("Pas de session active")
        return receive_encrypted_message(self.sock, self.session)

    def close(self):
        if hasattr(self, "sock"):
            self.sock.close()


# ── Test standalone ───────────────────────────────────────────────

if __name__ == "__main__":
    import threading

    print("\n🔐 Test Module 2.4 — Chiffrement des messages\n")

    node_alice = "alice_" + "a" * 58
    node_bob   = "bob___" + "b" * 58

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 19998))
    server_sock.listen(1)

    received = {}

    def bob_thread():
        conn, _ = server_sock.accept()
        session = perform_handshake_responder(conn, node_bob)
        msg     = receive_encrypted_message(conn, session)
        received["msg"] = msg
        conn.close()

    t = threading.Thread(target=bob_thread)
    t.start()

    # Alice se connecte et envoie un message
    alice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_sock.connect(("127.0.0.1", 19998))
    session_alice = perform_handshake_initiator(alice_sock, node_alice)
    send_encrypted_message(alice_sock, session_alice, node_alice, "Salut Bob depuis Archipel !")
    alice_sock.close()
    t.join()
    server_sock.close()

    assert received["msg"]["text"] == "Salut Bob depuis Archipel !"
    assert received["msg"]["from"] == node_alice
    print("\n  ✅ Message chiffré E2E envoyé et reçu correctement")
    print(f"  ✅ Contenu : {received['msg']['text']}")
    print("\n✅ Tous les tests Module 2.4 passent !\n")
