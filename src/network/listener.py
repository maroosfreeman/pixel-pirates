"""
Archipel — Module 1.1 : Récepteur UDP Multicast
Écoute les paquets HELLO des pairs sur 239.255.42.99:6000
Répond avec PEER_LIST en TCP unicast
"""

import socket
import struct
import threading
import time
import os
import sys
from pathlib import Path

# Import flexible pour PeerTable
try:
    from network.peer_table import PeerTable
except ImportError:
    src_dir = str(Path(__file__).resolve().parents[1])
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    from network.peer_table import PeerTable

# Import flexible pour tcp_server (encode_tlv)
try:
    from network.tcp_server import encode_tlv, TLV_PEER_LIST
except ImportError:
    src_dir = str(Path(__file__).resolve().parents[1])
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    from network.tcp_server import encode_tlv, TLV_PEER_LIST


def send_peer_list(target_ip: str, target_port: int, peer_table: PeerTable, node_id: str):
    """
    Envoie la liste des pairs connus en TCP unicast au nœud qui vient de dire HELLO.
    Conforme au Module 1.1 : Réponse PEER_LIST en unicast TCP.
    """
    try:
        peers = list(peer_table.peers.values())
        msg   = encode_tlv(TLV_PEER_LIST, {
            "node_id": node_id,
            "peers":   peers,
        })
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((target_ip, target_port))
            sock.sendall(msg)
            print(f"[UDP→TCP] 📋 PEER_LIST envoyée à {target_ip}:{target_port} ({len(peers)} pairs)")
        finally:
            sock.close()
    except Exception as e:
        print(f"[UDP→TCP] ⚠️ Impossible d'envoyer PEER_LIST à {target_ip}:{target_port} : {e}")


def start_listening(node_id: str, tcp_port: int = 7777):
    table = PeerTable()

    # Boucle d'affichage et de nettoyage toutes les 5 secondes
    def refresh_screen():
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            table.clean_old_peers()
            table.display()
            time.sleep(5)

    threading.Thread(target=refresh_screen, daemon=True).start()

    print("👂 Récepteur UDP Multicast actif sur 239.255.42.99:6000")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Windows : SO_REUSEPORT n'existe pas, on l'ignore proprement
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass

        sock.bind(('', 6000))

        # Rejoindre le groupe multicast 239.255.42.99
        group = socket.inet_aton('239.255.42.99')
        mreq  = struct.pack('4sL', group, socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        while True:
            data, addr = sock.recvfrom(1024)
            try:
                msg = data.decode().split('|')
            except UnicodeDecodeError:
                continue  # Paquet malformé, on ignore

            # Vérifie le type de paquet HELLO
            if len(msg) >= 3 and msg[0] == "HELLO":
                remote_node_id = msg[1]
                remote_port    = int(msg[2])

                # Ignore nos propres HELLOs
                if remote_node_id == node_id:
                    continue

                # Met à jour la peer table
                table.update_peer(remote_node_id, addr[0], remote_port)

                # Réponse PEER_LIST en TCP unicast dans un thread séparé
                threading.Thread(
                    target=send_peer_list,
                    args=(addr[0], remote_port, table, node_id),
                    daemon=True
                ).start()

    except KeyboardInterrupt:
        print("\nArrêt du récepteur.")
    finally:
        sock.close()


if __name__ == "__main__":
    import hashlib, secrets
    fake_id = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    start_listening(node_id=fake_id)