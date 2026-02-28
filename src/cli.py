"""
Archipel — Module 4.1 : Interface CLI
Assemblage de toutes les briques techniques P2P
"""

import argparse
import sys
import os
import time
import socket
import threading
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.identity import get_my_identity
from crypto.handshake import perform_handshake_initiator
from crypto.messaging import send_encrypted_message, send_encrypted_payload
from crypto.trust_store import TrustStore
from network.discovery import start_discovery
from network.listener import start_listening
from network.tcp_server import start_tcp_server
from network.peer_table import PeerTable
from network.packet import TYPE_MANIFEST
from transfer.chunking import LocalStorage, build_manifest
from transfer.transfer_manager import TransferManager

def get_node():
    my_signing_key, my_id = get_my_identity()
    return my_signing_key, my_id

def send_file_to_peer(filepath, peer_ip, peer_port, my_id, peer_id, my_signing_key):
    """Envoie un MANIFEST à un pair, initiant le téléchargement de son côté."""
    print(f"Envoi du fichier {filepath} à {peer_id[:16]}...")
    try:
        manifest = build_manifest(filepath, my_id, my_signing_key)
        
        # Stocke localement pour le servir plus tard
        storage = LocalStorage()
        storage.add_local_file(filepath, manifest)

        # Envoie le manifest au pair (via session chiffrée)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((peer_ip, int(peer_port)))
        session = perform_handshake_initiator(sock, my_id, my_signing_key)
        send_encrypted_payload(sock, session, TYPE_MANIFEST, my_id, manifest)
        sock.close()
        print("✅ Manifest envoyé. Le pair va initier le téléchargement en arrière-plan.")
        
    except Exception as e:
        print(f"❌ Erreur envoi fichier: {e}")

def main():
    parser = argparse.ArgumentParser(description="Archipel - Réseau P2P Décentralisé")
    subparsers = parser.add_subparsers(dest="command", help="Commandes disponibles")

    # Command: start
    parser_start = subparsers.add_parser("start", help="Démarrer le nœud (discovery, serveur TCP)")
    parser_start.add_argument("--port", type=int, default=7777, help="Port d'écoute TCP")
    parser_start.add_argument("--no-ai", action="store_true", help="Désactiver l'assistant IA")

    # Command: peers
    parser_peers = subparsers.add_parser("peers", help="Lister les pairs découverts")
    
    # Command: trust
    parser_trust = subparsers.add_parser("trust", help="Approuver un pair (Web of Trust)")
    parser_trust.add_argument("node_id", type=str)

    # Command: msg
    parser_msg = subparsers.add_parser("msg", help="Envoyer un message chiffré")
    parser_msg.add_argument("node_id", type=str)
    parser_msg.add_argument("text", type=str)

    # Command: send
    parser_send = subparsers.add_parser("send", help="Envoyer un fichier (génère et envoie un Manifest)")
    parser_send.add_argument("node_id", type=str)
    parser_send.add_argument("filepath", type=str)

    # Command: receive
    parser_recv = subparsers.add_parser("receive", help="Voir les fichiers locaux et en cours de dl")
    
    # Command: download
    parser_dl = subparsers.add_parser("download", help="Reprendre ou lancer le dl manuel d'un fichier")
    parser_dl.add_argument("file_id", type=str)

    parser_status = subparsers.add_parser("status", help="État du nœud")

    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)

    my_signing_key, my_id = get_node()
    peer_table = PeerTable()

    if args.command == "start":
        print(f"🚀 Lancement d'Archipel (Node ID: {my_id[:16]}...)")
        
        # 1. Start TCP Server (with storage)
        storage = LocalStorage()
        t_tcp = threading.Thread(target=start_tcp_server, args=(peer_table, my_id, my_signing_key, args.port), daemon=True)
        t_tcp.start()
        
        # 2. Start Multicast Listener (reçoit les UDP HELLO)
        t_list = threading.Thread(target=start_listening, args=(my_id, args.port), daemon=True)
        t_list.start()
        
        # 3. Start Multicast Discovery (envoie ses UDP HELLO)
        # Note: In a real environment, we would pass my_signing_key for signed HELLOs (Sprint 2)
        t_disc = threading.Thread(target=start_discovery, args=(args.port,), daemon=True)
        t_disc.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nArrêt du nœud Archipel.")
            sys.exit(0)

    elif args.command == "peers":
        peer_table.clean_old_peers()
        peer_table.display()

    elif args.command == "trust":
        store = TrustStore()
        # Fake signature to increase trust score, simplifed for hackathon
        store.sign_peer(args.node_id, my_id)
        print(f"✅ Pair {args.node_id[:16]}... approuvé.")

    elif args.command == "status":
        print(f"--- ARCHIPEL STATUS ---")
        print(f"Node ID: {my_id}")
        print(f"Pairs actifs: {len(peer_table.get_alive())}")
        storage = LocalStorage()
        print(f"Fichiers indexés: {len(storage.files)}")
        print(f"-----------------------")

    elif args.command == "msg":
        target = peer_table.peers.get(args.node_id)
        if not target:
            # Maybe looking up by short id?
            matches = [uid for uid in peer_table.peers if uid.startswith(args.node_id)]
            if not matches:
                print("❌ Pair non trouvé (assurez-vous que le nœud est allumé).")
                sys.exit(1)
            target = peer_table.peers[matches[0]]
            args.node_id = matches[0]
            
        # Si on demande à l'IA
        if "@archipel-ai" in args.text:
            try:
                from messaging.gemini_ai import query_gemini
                ai_reply = query_gemini("", args.text)
                print(f"🤖 IA: {ai_reply}")
            except Exception as e:
                print(f"⚠️ Erreur IA: {e}")
                
        # Send actual text to peer
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target["ip"], target["tcp_port"]))
            session = perform_handshake_initiator(sock, my_id, my_signing_key)
            send_encrypted_message(sock, session, my_id, args.text)
            sock.close()
        except OSError:
            print("❌ Impossible de joindre le pair.")

    elif args.command == "send":
        target = peer_table.peers.get(args.node_id)
        if not target:
            matches = [uid for uid in peer_table.peers if uid.startswith(args.node_id)]
            if not matches:
                print("❌ Pair non trouvé.")
                sys.exit(1)
            target = peer_table.peers[matches[0]]
            args.node_id = matches[0]
            
        send_file_to_peer(args.filepath, target["ip"], target["tcp_port"], my_id, args.node_id, my_signing_key)

    elif args.command == "receive":
        storage = LocalStorage()
        print("\n--- ARCHIPEL FILES ---")
        if not storage.files:
            print("Aucun fichier indexé.")
        for fid, finfo in storage.files.items():
            name = finfo["manifest"].get("filename", "?")
            chunks_have = len(finfo["chunks_have"])
            chunks_tot = finfo["manifest"].get("nb_chunks", 1)
            pct = int((chunks_have / chunks_tot) * 100)
            status = "✅ Complet" if pct == 100 else f"⏳ {pct}% ({chunks_have}/{chunks_tot})"
            print(f"  ID: {fid[:8]}... | Nom: {name:<20} | Statut: {status}")
        print("----------------------\n")

    elif args.command == "download":
        storage = LocalStorage()
        file_info = storage.files.get(args.file_id)
        if not file_info:
            print("❌ Fichier non trouvé dans l'index. Attendez de recevoir le MANIFEST.")
            sys.exit(1)
            
        if len(file_info["chunks_have"]) == file_info["manifest"]["nb_chunks"]:
            print("✅ Fichier déjà complètement téléchargé.")
            sys.exit(0)
            
        # Reprise du téléchargement auprès de son envoyeur originel (simplifié)
        manifest = file_info["manifest"]
        sender_id = manifest["sender_id"]
        target = peer_table.peers.get(sender_id)
        if not target:
            print("❌ L'hôte d'origine est injoignable.")
            sys.exit(1)
            
        mgr = TransferManager(storage, None)
        mgr.fetch_file(manifest, sender_id, target["ip"], target["tcp_port"])
        print("⏳ Téléchargement lancé en tâche de fond. Utilisez 'receive' pour voir le statut.")

if __name__ == "__main__":
    main()
