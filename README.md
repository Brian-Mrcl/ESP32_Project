# ESP32 - RFID Cloner · WiFi Sniffer · BLE Scanner

Plateforme d'expérimentation embarquée sur **ESP32** combinant :
- Lecture et clonage de badges **RFID MIFARE 1K** via module RC522
- **Sniffer WiFi passif** 802.11 pour analyser les trames réseau
- **Scanner BLE** pour identifier et analyser les périphériques Bluetooth à proximité

> ⚠️ **Avertissement légal** : Ces outils sont à usage **strictement éducatif et personnel**. L'interception de communications réseau sans autorisation est illégale dans la plupart des pays. N'utilisez jamais ces outils sur des réseaux ou appareils sans autorisation explicite du propriétaire.

---

## Table des matières

- [Matériel requis](#matériel-requis)
- [Projet 1 - RFID Cloner (RC522)](#projet-1--rfid-cloner-rc522)
- [Projet 2 - WiFi Sniffer](#projet-2--wifi-sniffer)
- [Projet 3 - BLE Scanner](#projet-3--ble-scanner)
- [Installation et configuration](#installation-et-configuration)
- [Structure du dépôt](#structure-du-dépôt)
- [Dépendances](#dépendances)
- [Concepts techniques](#concepts-techniques)
- [Limitations connues](#limitations-connues)

---

## Matériel requis

| Composant | Quantité | Utilisation |
|-----------|----------|-------------|
| ESP32 (DevKit v1 ou équivalent) | 1 | Microcontrôleur principal |
| Module RFID RC522 | 1 | Lecture/écriture badges MIFARE |
| Carte MIFARE 1K (à lire) | 1+ | Source pour lecture/dump |
| Carte MIFARE Magic / UID modifiable | 1 | Cible pour le clonage d'UID |
| Câbles Dupont | ~10 | Connexions |
| Breadboard (optionnel) | 1 | Prototypage |

Les projets WiFi Sniffer et BLE Scanner n'ont besoin que de l'**ESP32 seul** (pas de composant externe).

---

## Projet 1 - RFID Cloner (RC522)

### Description

Ce projet permet d'interagir avec des badges RFID MIFARE 1K en utilisant le module RC522. Il propose quatre fonctionnalités accessibles via un menu Serial :

1. **Lecture UID** - Identifie et affiche le numéro unique (UID) d'une carte ainsi que son type
2. **Dump complet** - Lit et affiche les 64 blocs (16 secteurs × 4 blocs) de la mémoire d'une carte MIFARE 1K en hexadécimal et ASCII
3. **Clone UID** - Écrit un UID prédéfini dans le bloc 0 d'une carte Magic (carte à UID modifiable)
4. **Vérification post-écriture** - Relit le bloc 0 après clonage pour confirmer la réussite

### Câblage RC522 → ESP32

```
RC522        ESP32
-------      -----
VCC    →     3.3V  (⚠ NE PAS utiliser 5V, le RC522 est 3.3V)
GND    →     GND
RST    →     GPIO 8
SDA    →     GPIO 7  (SS/CS)
SCK    →     GPIO 4
MISO   →     GPIO 5
MOSI   →     GPIO 6
IRQ    →     Non connecté
```

> 💡 **Important** : Le RC522 fonctionne en **3.3V uniquement**. Une alimentation 5V endommagera le module.

### Structure mémoire MIFARE 1K

```
Secteur 0
  Bloc 0  : Bloc fabricant (UID + données constructeur) ← Modifiable avec carte Magic
  Bloc 1  : Données utilisateur
  Bloc 2  : Données utilisateur
  Bloc 3  : Bloc Trailer (Clé A | Access Bits | Clé B)

Secteur 1-15 (identique)
  Bloc N*4+0 : Données utilisateur
  Bloc N*4+1 : Données utilisateur
  Bloc N*4+2 : Données utilisateur
  Bloc N*4+3 : Bloc Trailer
```

**Clé par défaut** : `FF FF FF FF FF FF` (utilisée pour l'authentification)

### Format du Bloc 0

```
Byte 0-3  : UID (4 bytes)
Byte 4    : BCC - Byte de vérification = UID[0] XOR UID[1] XOR UID[2] XOR UID[3]
Byte 5    : SAK
Byte 6-7  : ATQA
Byte 8-15 : Données fabricant
```

### Utilisation

1. Téléverser le code sur l'ESP32
2. Ouvrir le **Serial Monitor** à **115200 bauds**
3. Utiliser le menu affiché :
   - `1` → Lire UID d'une carte
   - `2` → Dump complet des 64 blocs
   - `3` → Cloner l'UID cible (`BE:22:AA:7B` par défaut)
   - `4` → Afficher l'UID cible configuré
   - `h` → Réafficher le menu

### Modifier l'UID cible à cloner

Dans `rfid_cloner.ino`, modifier la ligne :

```cpp
byte targetUID[] = {0xBE, 0x22, 0xAA, 0x7B};
```

Remplacer par les bytes de l'UID souhaité (4 bytes pour MIFARE 1K standard).

### Cartes Magic / UID modifiables

Les cartes MIFARE classiques ont leur **bloc 0 en lecture seule** - impossible d'y écrire. Les **cartes Magic** (aussi appelées "UID writable" ou "Gen1A") permettent l'écriture du bloc 0, ce qui rend possible le clonage d'UID.

Il existe deux générations :
- **Gen1A** : Répondent à une commande spéciale de déverrouillage avant l'écriture du bloc 0
- **Gen2** : Se comportent comme des cartes normales mais acceptent l'écriture du bloc 0 via la clé A

Ce code cible les cartes **Gen1A** et **Gen2** avec clé A par défaut.

---

## Projet 2 - WiFi Sniffer

### Description

Ce projet met l'ESP32 en **mode promiscuité WiFi**, ce qui lui permet de capturer toutes les trames 802.11 qui passent dans l'air sur un canal donné, sans être associé à aucun réseau.

Fonctionnalités :
- Capture de toutes les trames 802.11 (Management, Data, Control)
- Décodage des trames Management : Beacon, Probe Request/Response, Auth, Deauth, Association
- Extraction des SSID depuis les Beacons et Probe Responses
- Tracking des adresses MAC avec compteur de paquets et RSSI
- Statistiques détaillées par type de trame
- **Hop automatique** entre les canaux 1-13 (toutes les 2 secondes par défaut)
- Mode CSV pour export des données
- Menu interactif complet

### Types de trames capturées

| Type | Sous-type | Description |
|------|-----------|-------------|
| Management | Beacon | Broadcast d'un AP (SSID, capacités) |
| Management | Probe Request | Recherche d'un réseau par un client |
| Management | Probe Response | Réponse d'un AP à une Probe Request |
| Management | Auth | Authentification 802.11 |
| Management | Deauth | Déauthentification |
| Management | Assoc Request/Response | Association au réseau |
| Data | - | Données encryptées |
| Control | ACK, RTS, CTS... | Contrôle du medium |

### Utilisation

1. Téléverser le code sur l'ESP32
2. Ouvrir le **Serial Monitor** à **115200 bauds**
3. Les trames Management apparaissent en temps réel
4. Commandes disponibles :

| Commande | Action |
|----------|--------|
| `h` | Afficher le menu |
| `s` | Statistiques globales |
| `d` | Liste des appareils détectés |
| `c` | Activer/désactiver le hop de canal |
| `+` / `-` | Canal suivant / précédent (hop désactivé) |
| `m` | Filtrer trames Management uniquement |
| `a` | Afficher tous les types de trames |
| `v` | Toggle mode CSV |
| `r` | Remettre les stats à zéro |

### Exemple de sortie

```
[BEACON] CH:6  RSSI:-62dBm
  SRC  : AA:BB:CC:DD:EE:FF
  DST  : FF:FF:FF:FF:FF:FF
  BSSID: AA:BB:CC:DD:EE:FF
  SSID : MonReseau_5G

[PROBE_REQ] CH:6  RSSI:-78dBm
  SRC  : 11:22:33:44:55:66
  DST  : FF:FF:FF:FF:FF:FF
  BSSID: FF:FF:FF:FF:FF:FF
  SSID : AndroidAP
```

### Format CSV

```
timestamp,type,src_mac,dst_mac,bssid,rssi,channel
1234567,BEACON,AA:BB:CC:DD:EE:FF,FF:FF:FF:FF:FF:FF,AA:BB:CC:DD:EE:FF,-62,6
```

### Notes techniques

- L'ESP32 ne peut écouter qu'**un seul canal à la fois**. Le hop de canal simule un scan multi-canal mais peut manquer des trames sur un canal donné pendant le saut.
- Les trames **Data sont encryptées** (WPA2/WPA3) - le sniffer peut les compter mais pas les déchiffrer.
- Les adresses MAC peuvent être **randomisées** par les appareils modernes (iOS, Android, Windows 10+), ce qui limite le tracking MAC.

---

## Projet 3 - BLE Scanner

### Description

Ce projet utilise le contrôleur BLE intégré de l'ESP32 pour scanner passivement (ou activement) les **Advertisement Packets** des appareils Bluetooth Low Energy à proximité.

Fonctionnalités :
- Scan passif (écoute) ou actif (envoie des Scan Requests)
- Décodage des **Manufacturer Data** : détection iBeacon Apple, Eddystone Google
- Identification de l'entreprise fabricante via le **Company ID**
- Estimation de la distance via le **RSSI** (formule log-distance)
- Affichage des UUID de services exposés
- Tracking des appareils uniques avec historique (compteur de présence, première/dernière vue)
- Mode verbose avec affichage complet des données d'advertisement
- Export CSV des appareils détectés
- Scan continu automatique ou scan manuel

### Utilisation

1. Téléverser le code sur l'ESP32
2. Ouvrir le **Serial Monitor** à **115200 bauds**
3. Le scan démarre automatiquement en mode passif continu
4. Commandes disponibles :

| Commande | Action |
|----------|--------|
| `h` | Afficher le menu |
| `s` | Lancer un scan unique |
| `c` | Toggle scan continu auto |
| `a` | Toggle mode actif/passif |
| `v` | Toggle mode verbose |
| `l` | Liste tous les appareils détectés |
| `t` | Statistiques |
| `e` | Export CSV (prochain scan) |
| `r` | Reset complet |

### Exemple de sortie - Mode compact

```
[BLE] AA:BB:CC:DD:EE:FF  RSSI: -55dBm  iPhone         iBeacon              1.41m
[BLE] 11:22:33:44:55:66  RSSI: -72dBm  <unnamed>      Device [Samsung]     5.62m
[BLE] 77:88:99:AA:BB:CC  RSSI: -48dBm  Mi Band 6      Unknown              0.79m
```

### Exemple de sortie - Mode verbose

```
┌── Appareil BLE ──────────────────────────────┐
│ Adresse  : AA:BB:CC:DD:EE:FF
│ Nom      : <inconnu>
│ RSSI     : -55 dBm (Excellent)
│ Distance : ~1.41 m
│ Type     : iBeacon
│ Connectable : Non
│ [iBeacon] UUID: 2F234454 CF6D 4A0F AD F2 38 CC 43 16 5E
│ [iBeacon] Major: 1  Minor: 2  TxPower: -59 dBm
└──────────────────────────────────────────────┘
```

### Calcul de distance estimée

La distance est estimée via la **formule log-distance path loss** :

```
distance = 10 ^ ((TxPower - RSSI) / (10 * n))
```

Où :
- `TxPower` = puissance émise à 1m de référence (défaut : -59 dBm)
- `RSSI` = puissance reçue mesurée
- `n` = facteur d'atténuation environnemental (2.0 = espace libre, 3.0 = intérieur)

> ⚠️ Cette estimation est approximative. Les obstacles, réflexions et interférences peuvent fausser significativement la mesure.

### Types d'appareils reconnus

| Type | Identification | Description |
|------|---------------|-------------|
| iBeacon | Company ID `0x004C` + type `0x0215` | Balises Apple |
| Eddystone-UID | Service UUID `0xFEAA` + frame `0x00` | Balises Google (ID) |
| Eddystone-URL | Service UUID `0xFEAA` + frame `0x10` | Balises Google (URL) |
| Eddystone-TLM | Service UUID `0xFEAA` + frame `0x20` | Balises Google (Telemetry) |
| Device [Apple] | Company ID `0x004C` (non-iBeacon) | AirDrop, AirPods, etc. |
| Device [Google] | Company ID `0x00E0` | Appareils Android |
| Device [Samsung] | Company ID `0x0075` | Galaxy, etc. |

---

## Installation et configuration

### Prérequis

- [Arduino IDE](https://www.arduino.cc/en/software) **2.x** ou **PlatformIO**
- Support ESP32 pour Arduino IDE

### Installation du support ESP32

Dans Arduino IDE : `Fichier → Préférences → URL de gestionnaire de cartes supplémentaires` :

```
https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
```

Puis : `Outils → Gestionnaire de cartes` → Chercher "esp32" → Installer **esp32 by Espressif Systems**

### Bibliothèques requises

| Bibliothèque | Projet | Installation |
|---|---|---|
| `MFRC522` by GithubCommunity | RFID | Gestionnaire de bibliothèques Arduino |
| `ESP32 BLE Arduino` | BLE | Incluse avec le support ESP32 |
| WiFi promiscuous API | WiFi | Incluse dans l'IDF ESP32 (pas d'install) |

Installation MFRC522 : `Outils → Gérer les bibliothèques → "MFRC522"` → Installer

### Configuration de la carte

- **Carte** : `ESP32 Dev Module` (ou votre variante)
- **Upload Speed** : `921600`
- **CPU Frequency** : `240MHz`
- **Flash Size** : `4MB`
- **Partition Scheme** : `Default 4MB with spiffs`

### Téléversement

1. Ouvrir le fichier `.ino` souhaité dans Arduino IDE
2. Sélectionner la bonne carte et port COM
3. Cliquer sur **Téléverser** (→)
4. Ouvrir le **Serial Monitor** à **115200 bauds**

---

## Structure du dépôt

```
esp32-rfid-wifi-ble/
│
├── rfid_rc522/
│   └── rfid_cloner.ino          # Code RFID complet
│
├── wifi_sniffer/
│   └── wifi_sniffer.ino         # Code WiFi Sniffer
│
├── ble_scanner/
│   └── ble_scanner.ino          # Code BLE Scanner
│
└── README.md                    # Ce fichier
```

---

## Dépendances

### RFID

```cpp
#include <SPI.h>      // Incluse avec Arduino / ESP32
#include <MFRC522.h>  // À installer via le gestionnaire de bibliothèques
```

### WiFi Sniffer

```cpp
#include "esp_wifi.h"   // Incluse dans l'IDF ESP32
#include "esp_event.h"  // Incluse dans l'IDF ESP32
#include "nvs_flash.h"  // Incluse dans l'IDF ESP32
```

> Le WiFi Sniffer utilise directement l'**ESP-IDF** (pas la bibliothèque Arduino WiFi.h) pour accéder au mode promiscuité bas niveau.

### BLE Scanner

```cpp
#include <BLEDevice.h>          // Incluse avec support ESP32
#include <BLEScan.h>            // Incluse avec support ESP32
#include <BLEAdvertisedDevice.h>
```

---

## Concepts techniques

### RFID MIFARE 1K

Le protocole **MIFARE Classic 1K** utilise ISO/IEC 14443-A à 13.56 MHz. La mémoire est organisée en 16 secteurs de 4 blocs de 16 bytes. Chaque secteur est protégé par deux clés (A et B) définies dans le bloc Trailer. La communication utilise un chiffrement propriétaire CRYPTO-1.

### 802.11 - Trames WiFi

Les réseaux WiFi utilisent trois types de trames :
- **Management** : gestion de la connexion (découverte réseau, authentification, association)
- **Control** : coordination de l'accès au medium (ACK, RTS/CTS)
- **Data** : transfert des données utilisateur

En mode promiscuité, l'ESP32 reçoit toutes les trames sur le canal actif sans être associé.

### BLE - Bluetooth Low Energy

Le BLE utilise 40 canaux radio de 2 MHz entre 2.400 GHz et 2.4835 GHz. Les **Advertisement Packets** sont envoyés sur 3 canaux primaires dédiés (37, 38, 39). Les données d'advertisement contiennent des **AD Structures** qui encodent le nom, les services, et les données fabricant selon le format défini par le Bluetooth SIG.

---

## Limitations connues

### RFID

- Fonctionne uniquement avec les cartes **MIFARE Classic** (1K, Mini, 4K). Incompatible avec MIFARE DESFire, NTAG, etc.
- Le clonage d'UID ne fonctionne que sur les cartes **Magic** (Gen1A/Gen2)
- La clé d'authentification utilisée est la clé par défaut `FF FF FF FF FF FF`. Les cartes avec des clés personnalisées ne pourront pas être lues/modifiées sans connaître la clé

### WiFi Sniffer

- L'ESP32 ne peut écouter qu'**un canal à la fois** - le hop de canal induit des pertes sur les autres canaux
- Les trames Data sont **encryptées** (WPA2/3) et ne peuvent pas être déchiffrées
- Les appareils modernes utilisent des **adresses MAC aléatoires** (MAC randomization) - le tracking MAC réel est limité
- Les canaux 12/13 peuvent être restreints selon la réglementation locale

### BLE Scanner

- La **distance estimée** est une approximation - précision de ±30% en conditions réelles
- Les appareils utilisant la **privacy BLE** (adresse MAC aléatoire rotative) apparaissent comme plusieurs appareils différents
- Le scan passif ne capture que les **Advertisement Packets non sollicités** - certains appareils nécessitent un scan actif

---

## Licence

Projet personnel à usage éducatif. Voir les lois locales concernant l'utilisation de ces techniques avant tout déploiement.
