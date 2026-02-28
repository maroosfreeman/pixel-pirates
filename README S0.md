
## Livrable Sprint 0 — Bootstrap & Architecture

## Stack Technique

Le cœur d'Archipel repose sur **Python 3.11+ avec asyncio** comme langage principal. Dans le contexte d'un hackathon de 24 heures, la productivité prime sur la performance brute, et Python offre l'écosystème cryptographique le plus mature et le plus accessible qui soit.

Pour le transport local, Archipel combine deux technologies complémentaires tirées directement du sujet. La découverte des pairs repose sur UDP Multicast à l'adresse 239.255.42.99:6000 : chaque nœud émet un paquet HELLO toutes les 30 secondes à l'ensemble du réseau local, sans établir de connexion, sans cibler un pair en particulier. C'est léger, instantané, et ne nécessite aucune configuration préalable. Une fois les pairs identifiés, le transfert des données bascule sur TCP Sockets (port 7777) : la connexion point-à-point garantit la fiabilité des échanges, le contrôle de flux, et la livraison ordonnée des chunks — indispensable pour des transferts de fichiers volumineux.
Cette combinaison UDP + TCP est exactement celle préconisée par le document technique : chaque protocole intervient là où il excelle.

Une fois les pairs connus, les transferts de données transitent via **TCP sur le port 7777** avec un encodage TLV (Type-Length-Value). Le protocole TCP garantit la fiabilité des échanges et assure un contrôle de flux natif, indispensable pour des transferts de fichiers volumineux.

La couche cryptographique s'appuie sur **PyNaCl et PyCryptodome**, deux bibliothèques de référence dans l'industrie. PyNaCl fournit des bindings directs vers libsodium — l'une des implémentations cryptographiques les plus auditées au monde — tandis que PyCryptodome complète l'ensemble pour les primitives symétriques.

L'interface utilisateur combine un **CLI interactif via la bibliothèque rich** pour les démonstrations rapides en terminal, et une **UI Web légère construite avec aiohttp** pour une présentation plus visuelle devant le jury.

Enfin, le stockage local des métadonnées et des index de chunks repose sur **SQLite ou JSON selon les besoins**. Ce choix délibéré élimine toute dépendance d'infrastructure : aucun serveur de base de données, aucune configuration, un simple fichier sur le disque.


## Schéma d'Architecture

┌─────────────────────────────────────────────────────────────────┐
│                     RÉSEAU LOCAL (LAN/WiFi)                     │
│                                                                 │
│   ┌──────────┐   UDP Multicast (découverte)  ┌──────────┐      │
│   │  Nœud A  │──────────────────────────────►│  Nœud B  │      │
│   │          │   239.255.42.99:6000  HELLO   │          │      │
│   │ Ed25519  │◄──────────────────────────────│ Ed25519  │      │
│   │  KeyPair │                               │  KeyPair │      │
│   │          │   TCP :7777 (transfert E2E)   │          │      │
│   │          │◄─────════════════════════════►│          │      │
│   └────┬─────┘                               └────┬─────┘      │
│        │                                          │            │
│        │         TCP :7777 (transfert E2E)        │            │
│        └──────────════════════════════════────────┘            │
│                          │                                      │
│                     ┌────▼─────┐                               │
│                     │  Nœud C  │   Chaque nœud :               │
│                     │          │   • UDP Multicast → HELLO     │
│                     │ Ed25519  │   • TCP → transfert chiffré   │
│                     │  KeyPair │   • Chunks BitTorrent-style   │
│                     └──────────┘   • Web of Trust (TOFU)      │
└─────────────────────────────────────────────────────────────────┘




## Format de Paquet ARCK v1

┌──────────┬─────────┬────────┬───────┬─────────────┬──────────┐
│  MAGIC   │ VERSION │  TYPE  │ FLAGS │ PAYLOAD_LEN │ CHECKSUM │
│  "ARCK"  │  0x01   │ 1 byte │1 byte │   4 bytes   │  4 bytes │
│  4 bytes │ 1 byte  │        │       │             │  SHA-256 │
├──────────┴─────────┴────────┴───────┴─────────────┴──────────┤
│                    SENDER_ID (32 bytes)                       │
│              Clé publique Ed25519 = identité nœud             │
├───────────────────────────────────────────────────────────────┤
│                     NONCE (12 bytes)                          │
│               AES-GCM nonce unique par paquet                 │
├───────────────────────────────────────────────────────────────┤
│                    PAYLOAD (N bytes)                          │
│            Chiffré AES-256-GCM si FLAG_ENCRYPTED              │
├───────────────────────────────────────────────────────────────┤
│                  SIGNATURE (64 bytes)                         │
│              Ed25519 sur (header + payload)                   │
└───────────────────────────────────────────────────────────────┘

Header fixe   : 59 bytes
Signature     : 64 bytes
Taille min    : 123 bytes
### Types de paquets

| Code | Nom | Usage |
|------|-----|-------|
| `0x01` | `HELLO` | Annonce de présence UDP toutes les 30s |
| `0x02` | `PEER_LIST` | Liste des pairs connus (TCP unicast) |
| `0x03` | `HANDSHAKE_INIT` | Initiation du handshake chiffré |
| `0x04` | `HANDSHAKE_ACK` | Confirmation handshake |
| `0x10` | `MESSAGE` | Message texte chiffré |
| `0x20` | `FILE_MANIFEST` | Annonce d'un fichier disponible |
| `0x21` | `CHUNK_REQUEST` | Demande d'un chunk |
| `0x22` | `CHUNK_DATA` | Données d'un chunk |
| `0x23` | `CHUNK_ACK` | Confirmation de réception |
| `0xF0` | `PING` | Keep-alive |
| `0xF1` | `PONG` | Réponse keep-alive |
| `0xFE` | `REVOKE` | Révocation de clé compromise |
| `0xFF` | `ERROR` | Erreur protocole |



## Guide de démo

```bash
# Terminal 1 — Premier nœud
python -m src.cli.main --port 7777

# Terminal 2 — Second nœud (même LAN ou localhost)
python -m src.cli.main --port 7778

# Commandes CLI :
#   /peers          — liste les pairs découverts
#   /send <msg>     — envoie un message chiffré
#   /share <file>   — partage un fichier (chunking)
#   /get <hash>     — télécharge un fichier par hash
#   /ask <question> — interroge l'assistant Gemini
```
