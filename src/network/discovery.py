"""
Archipel — Module 1.1 : Émetteur UDP Multicast (Discovery)
Émet un paquet HELLO toutes les 30 secondes sur 239.255.42.99:6000
"""

import socket
import time
import sys
from pathlib import Path

# Import flexible pour `get_my_identity` (se trouve dans src/crypto/identity.py)
try:
    from crypto.identity import get_my_identity
except Exception:
    # Si execution en tant que script direct, ajoute `src/` au sys.path puis réessaie
    try:
        src_dir = str(Path(__file__).resolve().parents[1])
        if src_dir not in sys.path:
            sys.path.insert(0, src_dir)
        from crypto.identity import get_my_identity
    except Exception:
        # Dernier recours : cherche un module local `get_my_identity.py`
        try:
            from get_my_identity import get_my_identity  # type: ignore
        except Exception as e:
            raise ImportError(
                "Impossible d'importer 'get_my_identity' (crypto.identity) "
                "-> vérifiez le chemin d'exécution"
            ) from e

try:
    from network.packet import build_json_packet, TYPE_HELLO
except ImportError:
    src_dir = str(Path(__file__).resolve().parents[1])
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    from network.packet import build_json_packet, TYPE_HELLO

MULTICAST_GROUP = '239.255.42.99'
PORT = 6000


def start_discovery(tcp_port: int = 7777):
    # signing_key inutilisé au Sprint 1 — sera utilisé au Sprint 2 pour signer les HELLO
    _, my_id = get_my_identity()

    print(f"📡 Émetteur lancé (ID: {my_id[:10]}…)")

    # Socket créé DANS le try pour garantir la fermeture dans tous les cas
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        while True:
            # Format réseau (Magic + Type + NodeId + Len + Payload + HMAC)
            pkt = build_json_packet(TYPE_HELLO, my_id, {"tcp_port": tcp_port})
            sock.sendto(pkt, (MULTICAST_GROUP, PORT))
            print(f"📢 HELLO envoyé à {time.strftime('%H:%M:%S')}")
            time.sleep(30)  # Intervalle de 30s selon le sujet

    except KeyboardInterrupt:
        print("\nArrêt de l'émetteur.")
    finally:
        sock.close()


if __name__ == "__main__":
    start_discovery()