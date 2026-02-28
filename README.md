# ARCHIPEL — Protocole P2P Chiffré et Décentralisé

## 1. Description du Protocole Archipel
Archipel est un protocole de communication Peer-to-Peer (P2P) conçu pour fonctionner sur un réseau local pur (zéro connexion Internet externe), sans serveur central ni tracker DNS. 

Chaque membre du réseau (un nœud) agit à la fois comme client et comme serveur décentralisé. Le système garantit la sécurité et l'identité des paires grâce à une cryptographie forte asymétrique (Ed25519) et symétrique (AES-256-GCM), ainsi qu'une politique de confiance distribuée (*Web of Trust*).

## 2. Architecture et Choix Techniques

### Discovery (Module Réseau Multicast)
- **Technologie :** UDP Multicast (groupe `239.255.42.99:6000`).
- **Choix technique :** Sur de petits réseaux LAN, le multicast évite d'avoir à connaître les adresses IP à l'avance et ne requiert pas de point d'accès Wi-Fi ou de tracker externe.
- **Principe :** Chaque nœud émet un paquet `HELLO` toutes les 30s. Si un nouveau pair reçoit un `HELLO`, il lui répond en TCP Unicast avec sa `PEER_LIST`.

### Cryptographie & Handshake (Séquence à 3 temps)
- **Technologie :** `libsodium` / `cryptography` via PyNaCl.
- Séquence de poignée de main cryptographique inspirée de *Noise Protocol* entre Alice (Initiatrice) et Bob (Rondant) :
  1. `INIT` : Alice envoie sa clé publique éphémère (X25519).
  2. `ACK` : Bob répond avec sa clé publique éphémère (X25519) et un `salt`. Bob et Alice peuvent dès lors dériver une clé de session symétrique `session_key = HKDF(shared_secret, salt)`.
  3. `AUTH` : Alice s'authentifie formellement en confirmant l'ouverture de sa session via sa clé à long-terme **Ed25519** (ce qui évite les attaques Man-In-The-Middle, *MITM*).

### Le Web Of Trust (TOFU)
Au lieu d'utiliser une Autorité de Certification (CA), le réseau s'appuie sur le *Trust On First Use (TOFU)*. L'empreinte cryptographique permanente (`fingerprint` basée sur Ed25519) d'un premier pair est enregistrée de manière persistante. Toute future connexion du même ID provenant d'une clé différente sera rejetée (MITM bloqué).

### Format de Paquet Binaire Strict
Conformément au cahier des charges, l'échange n'est pas de simples chaînes. Chaque paquet contient un en-tête de 41 octets :
`MAGIC(4) | TYPE(1) | NODE_ID(32) | PAYLOAD_LEN(4)` suivi du `PAYLOAD` chiffré JSON et du `HMAC-SHA256(32)`.

### Chunking et Partage (Sprint 3)
Fichiers divisés en "Chunks" de 512 KB. L'expéditeur génère un paquet `MANIFEST` contenant les index et les signatures de chaque morceau, ce qui permet des transferts asynchrones (et potentiellement parallèles côté client).

### Intégration IA (Sprint 4)
Gemini 2.5 ("@archipel-ai") est intégré dans le client CLI pour interpréter localement un message sans exposer l'intégralité du réseau.

## 3. Modifications apportées pour le Hackathon

L'implémentation de départ a été modifiée en profondeur afin de satisfaire à 100% le cahier des charges de "LOME BUSINESS SCHOOL" :

1. **Format des Paquets Binaires Spécifiques :** Suppression des payloads simples (ex: `f"HELLO|node"`) au profit du protocole binaire avec headers structurés dans `src/network/packet.py` (Spécification S0 validée).
2. **Persistance des données Peer Table :** La table de peers a été enrichie d'une mécanique `self._save()` et `self._load()` écrivant sur le disque au format JSON (dans `.archipel/`) pour retenir les pairs entre deux connexions (Spécification S1).
3. **Refonte complète du TCP Server & Handshake :** Implémentation du système `Handshake` à trois tours avec échange d'identité permanente signée (`INIT` -> `ACK` -> `AUTH`) (Spécification S2).
4. **Implémentation de Chunking Fichiers :** Création du dossier `src/transfer/`, de la logique de calcul de SHA-256 et du téléchargement asynchrone pour passer des fichiers supérieurs à 50 Mo (Spécification S3).
5. **CLI Principal et Intégration Gemini :** Création du script `cli.py` en racine de l'application permettant d'invoquer via Arguments terminaux les différentes commandes demandées par le Jury. L'appel explicite de tag `@archipel-ai` déclenche l'appel externe à `Gemini` (Spécification S4).

## 4. Instructions d'Utilisation / Demo

### Pré-requis
- Python 3.9+
- Les bibliothèques listées dans le `requirements.txt` (notamment `cryptography` ou `PyNaCl`).
- Clé Google Gemini définie dans l'environnement `export GEMINI_API_KEY="...apikey..."` (uniquement si test de l'IA).

### Lancer la Plateforme et la Démo

Générer sa propre identité :
```bash
python src/clé.py --name Alice
```

1. **Démarrer le nœud (Fenêtre Terminal 1) :**
```bash
python src/cli.py start --port 7777
```
*(Le serveur se mettra alors à diffuser des paquets UDP toutes les 30s. Ouvrez un nœud sur une machine B pour voir les connexions s'établir)*

2. **Lister les voisins :**
```bash
python src/cli.py peers
```

3. **Envoyer un message à un autre nœud chiffré :**
```bash
python src/cli.py msg [NODE_ID] "Salut Bob, comment vas-tu ?"
# Et pour parler à l'IA :
python src/cli.py msg [NODE_ID] "@archipel-ai Résume le message précédent s'il te plaît"
```

4. **Transférer un Fichier Volumineux (50Mo) :**
Générez un fichier de test :
```bash
# Permet de cibler l'envoi
python src/cli.py send [NODE_ID] mon_gros_fichier.zip
```

Une fois validé, la machine B recevra une notification `MANIFEST reçu`. Depuis Node B, tapez :
```bash
python src/cli.py download [FILE_ID]
```

### Simulation / Flow Hackathon Complet
Voici les étapes exactes que nous avons suivies pour compléter l'ensemble des Sprints jusqu'au bout, ainsi que l'architecture qui tourne désormais en locale :

1. Configuration
```bash
python src/clé.py --name Alice
# et sur le node 2:
python src/clé.py --name Bob
```

2. Lancement du "Server" Alice :
```bash
python src/cli.py start
```

3. Interroger tes pairs via le "Client" Bob (dans un terminal 2), envoyer un message puis un fichier compressé de ton choix :
```bash
python src/cli.py msg [NODE_ID_ALICE] "Hello Archipel!"
python src/cli.py send [NODE_ID_ALICE] path/vers/un/fichier.zip
```

3. Lancer un rapatriement de Fichier depuis Bob (si on passe en MANIFEST Rarest)
```bash
python src/cli.py download [FILE_ID]
python src/cli.py receive
```

## Membres de l'équipe
- AI Assistant : Support complet des sprints (Réseau Binaire, Chunking, Intégration Interface)
- Toi : Planification stratégique et validation des exigences !

🎉 **Bonne chance. Construisez quelque chose qui mérite de survivre.** 
