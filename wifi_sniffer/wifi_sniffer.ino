/*
 * ============================================================
 *  ESP32 - WiFi Sniffer (Promiscuous Mode)
 *  Auteur : Projet Personnel
 * ============================================================
 *
 *  Fonctionnalités :
 *    - Mode promiscuité WiFi pour capturer les trames 802.11
 *    - Décodage des trames Management (Probe, Beacon, Auth...)
 *    - Décodage des trames Data et Control
 *    - Affichage SSID, BSSID, RSSI, canal, type de trame
 *    - Statistiques en temps réel
 *    - Hop de canaux automatique ou manuel
 *    - Filtrage par type de trame via Serial
 *    - Export CSV via Serial
 *
 *  Note : Usage strictement légal et éducatif.
 *         Ne pas utiliser sur des réseaux sans autorisation.
 * ============================================================
 */

#include <Arduino.h>
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include <map>
#include <vector>

// ─── Configuration ────────────────────────────────────────────
#define CHANNEL_HOP_INTERVAL_MS  2000   // Intervalle hop de canal (ms)
#define MAX_SSID_LEN             33
#define DISPLAY_STATS_INTERVAL   5000   // Affichage stats toutes les 5s
#define MAX_TRACKED_DEVICES      100    // Max appareils trackés

// ─── Types de trames 802.11 ───────────────────────────────────
#define FRAME_TYPE_MANAGEMENT    0x00
#define FRAME_TYPE_CONTROL       0x01
#define FRAME_TYPE_DATA          0x02

// Sous-types Management
#define MGMT_ASSOC_REQ           0x00
#define MGMT_ASSOC_RESP          0x01
#define MGMT_REASSOC_REQ         0x02
#define MGMT_REASSOC_RESP        0x03
#define MGMT_PROBE_REQ           0x04
#define MGMT_PROBE_RESP          0x05
#define MGMT_BEACON              0x08
#define MGMT_DISASSOC            0x0A
#define MGMT_AUTH                0x0B
#define MGMT_DEAUTH              0x0C

// ─── Structures ───────────────────────────────────────────────
typedef struct {
  uint16_t frame_ctrl;
  uint16_t duration;
  uint8_t  addr1[6];  // Destination
  uint8_t  addr2[6];  // Source
  uint8_t  addr3[6];  // BSSID
  uint16_t seq_ctrl;
  uint8_t  payload[0];
} __attribute__((packed)) wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0];
} __attribute__((packed)) wifi_ieee80211_packet_t;

// Structure pour un appareil détecté
struct DeviceInfo {
  uint8_t  mac[6];
  int8_t   rssi;
  uint8_t  channel;
  uint32_t lastSeen;
  uint32_t packetCount;
  char     ssid[MAX_SSID_LEN];
  bool     isAP;
};

// ─── Variables globales ───────────────────────────────────────
static uint8_t currentChannel = 1;
static bool    channelHopEnabled = true;
static bool    csvMode = false;
static bool    filterEnabled = false;
static uint8_t filterType = FRAME_TYPE_MANAGEMENT;

// Statistiques
static uint32_t totalPackets   = 0;
static uint32_t mgmtPackets    = 0;
static uint32_t dataPackets    = 0;
static uint32_t ctrlPackets    = 0;
static uint32_t beaconCount    = 0;
static uint32_t probeReqCount  = 0;
static uint32_t probeRespCount = 0;
static uint32_t deauthCount    = 0;

// Map MAC -> DeviceInfo
static std::map<uint64_t, DeviceInfo> devices;

static uint32_t lastHopTime    = 0;
static uint32_t lastStatsTime  = 0;

// ─── Helpers ──────────────────────────────────────────────────

uint64_t macToUint64(const uint8_t* mac) {
  uint64_t result = 0;
  for (int i = 0; i < 6; i++) result = (result << 8) | mac[i];
  return result;
}

void printMAC(const uint8_t* mac) {
  Serial.printf("%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char* getFrameTypeName(uint8_t type, uint8_t subtype) {
  if (type == FRAME_TYPE_MANAGEMENT) {
    switch (subtype) {
      case MGMT_BEACON:        return "BEACON";
      case MGMT_PROBE_REQ:     return "PROBE_REQ";
      case MGMT_PROBE_RESP:    return "PROBE_RESP";
      case MGMT_AUTH:          return "AUTH";
      case MGMT_DEAUTH:        return "DEAUTH";
      case MGMT_ASSOC_REQ:     return "ASSOC_REQ";
      case MGMT_ASSOC_RESP:    return "ASSOC_RESP";
      case MGMT_DISASSOC:      return "DISASSOC";
      default:                 return "MGMT_OTHER";
    }
  } else if (type == FRAME_TYPE_DATA) {
    return "DATA";
  } else if (type == FRAME_TYPE_CONTROL) {
    switch (subtype) {
      case 0x08: return "CTRL_BLOCKACK_REQ";
      case 0x09: return "CTRL_BLOCKACK";
      case 0x0A: return "CTRL_PS_POLL";
      case 0x0B: return "CTRL_RTS";
      case 0x0C: return "CTRL_CTS";
      case 0x0D: return "CTRL_ACK";
      default:   return "CTRL_OTHER";
    }
  }
  return "UNKNOWN";
}

// Extraction SSID depuis les IEs (Information Elements)
bool extractSSID(const uint8_t* payload, int payloadLen, char* ssid) {
  int idx = 0;

  // Pour beacon/probe resp, skip fixed params (12 bytes)
  // Pour probe req, skip fixed params (0 bytes)
  // On essaie directement
  while (idx < payloadLen - 2) {
    uint8_t elemId  = payload[idx];
    uint8_t elemLen = payload[idx + 1];

    if (idx + 2 + elemLen > payloadLen) break;

    if (elemId == 0) { // SSID element
      int len = min((int)elemLen, MAX_SSID_LEN - 1);
      if (len == 0) {
        strncpy(ssid, "<hidden>", MAX_SSID_LEN);
      } else {
        memcpy(ssid, &payload[idx + 2], len);
        ssid[len] = '\0';
        // Remplacement des chars non imprimables
        for (int i = 0; i < len; i++) {
          if (!isPrintable(ssid[i])) ssid[i] = '?';
        }
      }
      return true;
    }
    idx += 2 + elemLen;
  }
  return false;
}

// ─── Callback promiscuous ─────────────────────────────────────

void IRAM_ATTR wifi_sniffer_packet_handler(
    void* buf, wifi_promiscuous_pkt_type_t type)
{
  if (type == WIFI_PKT_MISC) return;

  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  const wifi_pkt_rx_ctrl_t& rxCtrl  = pkt->rx_ctrl;
  const wifi_ieee80211_packet_t* ipkt =
      (const wifi_ieee80211_packet_t*)pkt->payload;
  const wifi_ieee80211_mac_hdr_t* hdr = &ipkt->hdr;

  uint16_t fc       = hdr->frame_ctrl;
  uint8_t  frameType    = (fc >> 2) & 0x03;
  uint8_t  frameSubtype = (fc >> 4) & 0x0F;

  totalPackets++;

  if (frameType == FRAME_TYPE_MANAGEMENT) mgmtPackets++;
  else if (frameType == FRAME_TYPE_DATA)  dataPackets++;
  else if (frameType == FRAME_TYPE_CONTROL) ctrlPackets++;

  // Stats par sous-type
  if (frameType == FRAME_TYPE_MANAGEMENT) {
    if (frameSubtype == MGMT_BEACON)      beaconCount++;
    if (frameSubtype == MGMT_PROBE_REQ)   probeReqCount++;
    if (frameSubtype == MGMT_PROBE_RESP)  probeRespCount++;
    if (frameSubtype == MGMT_DEAUTH)      deauthCount++;
  }

  // Filtrage
  if (filterEnabled && frameType != filterType) return;

  // Tracking des appareils (source MAC)
  uint64_t srcMAC = macToUint64(hdr->addr2);
  if (devices.size() < MAX_TRACKED_DEVICES || devices.count(srcMAC)) {
    DeviceInfo& dev = devices[srcMAC];
    memcpy(dev.mac, hdr->addr2, 6);
    dev.rssi       = rxCtrl.rssi;
    dev.channel    = rxCtrl.channel;
    dev.lastSeen   = millis();
    dev.packetCount++;

    // Extraction SSID pour beacon et probe
    if (frameType == FRAME_TYPE_MANAGEMENT &&
        (frameSubtype == MGMT_BEACON || frameSubtype == MGMT_PROBE_RESP)) {
      dev.isAP = true;
      int payloadOffset = sizeof(wifi_ieee80211_mac_hdr_t) + 12; // +12 fixed params
      int payloadLen    = pkt->rx_ctrl.sig_len - payloadOffset;
      if (payloadLen > 0) {
        extractSSID(pkt->payload + payloadOffset, payloadLen, dev.ssid);
      }
    }
  }

  // ─── Affichage ────────────────────────────────────────────

  if (csvMode) {
    // Format CSV
    Serial.printf("%lu,%s,", millis(),
                  getFrameTypeName(frameType, frameSubtype));
    printMAC(hdr->addr2); Serial.print(',');
    printMAC(hdr->addr1); Serial.print(',');
    printMAC(hdr->addr3); Serial.print(',');
    Serial.printf("%d,%d\n", rxCtrl.rssi, rxCtrl.channel);
    return;
  }

  // Affichage lisible — Management uniquement par défaut
  if (frameType == FRAME_TYPE_MANAGEMENT) {
    const char* frameName = getFrameTypeName(frameType, frameSubtype);

    Serial.printf("\n[%s] CH:%d  RSSI:%ddBm\n",
                  frameName, rxCtrl.channel, rxCtrl.rssi);
    Serial.print  (F("  SRC  : ")); printMAC(hdr->addr2); Serial.println();
    Serial.print  (F("  DST  : ")); printMAC(hdr->addr1); Serial.println();
    Serial.print  (F("  BSSID: ")); printMAC(hdr->addr3); Serial.println();

    // Affichage SSID si disponible
    if (frameSubtype == MGMT_BEACON || frameSubtype == MGMT_PROBE_RESP ||
        frameSubtype == MGMT_PROBE_REQ) {
      int payloadOffset = sizeof(wifi_ieee80211_mac_hdr_t);
      if (frameSubtype != MGMT_PROBE_REQ) payloadOffset += 12;
      int payloadLen = pkt->rx_ctrl.sig_len - payloadOffset;
      if (payloadLen > 0) {
        char ssid[MAX_SSID_LEN] = {0};
        if (extractSSID(pkt->payload + payloadOffset, payloadLen, ssid)) {
          Serial.printf("  SSID : %s\n", ssid);
        }
      }
    }

    if (frameSubtype == MGMT_DEAUTH) {
      uint16_t reason = 0;
      int payloadOffset = sizeof(wifi_ieee80211_mac_hdr_t);
      if (pkt->rx_ctrl.sig_len > payloadOffset + 1) {
        reason = pkt->payload[payloadOffset] | (pkt->payload[payloadOffset+1] << 8);
      }
      Serial.printf("  REASON: %d\n", reason);
    }
  }
}

// ─── Hop de canal ─────────────────────────────────────────────

void hopChannel() {
  currentChannel = (currentChannel % 13) + 1;
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
}

// ─── Affichage des stats ──────────────────────────────────────

void printStats() {
  Serial.println(F("\n╔═══════════ STATISTIQUES ══════════════╗"));
  Serial.printf (  "║ Total paquets  : %-20lu║\n", totalPackets);
  Serial.printf (  "║ Management     : %-20lu║\n", mgmtPackets);
  Serial.printf (  "║ Data           : %-20lu║\n", dataPackets);
  Serial.printf (  "║ Control        : %-20lu║\n", ctrlPackets);
  Serial.println(F("║──────────────────────────────────────║"));
  Serial.printf (  "║ Beacons        : %-20lu║\n", beaconCount);
  Serial.printf (  "║ Probe Requests : %-20lu║\n", probeReqCount);
  Serial.printf (  "║ Probe Responses: %-20lu║\n", probeRespCount);
  Serial.printf (  "║ Deauth         : %-20lu║\n", deauthCount);
  Serial.println(F("║──────────────────────────────────────║"));
  Serial.printf (  "║ Appareils vus  : %-20u║\n", (unsigned)devices.size());
  Serial.printf (  "║ Canal actuel   : %-20d║\n", currentChannel);
  Serial.printf (  "║ Hop auto       : %-20s║\n", channelHopEnabled ? "OUI" : "NON");
  Serial.println(F("╚══════════════════════════════════════╝"));
}

void printDeviceList() {
  Serial.println(F("\n── Appareils détectés ──────────────────────────────────────"));
  Serial.println(F("MAC               | RSSI  | CH | Paquets | SSID / Type"));
  Serial.println(F("------------------|-------|----|---------|-------------"));

  int count = 0;
  for (auto& entry : devices) {
    const DeviceInfo& d = entry.second;
    printMAC(d.mac);
    Serial.printf(" | %4ddBm | %2d | %7lu | %s\n",
                  d.rssi, d.channel, d.packetCount,
                  d.isAP ? (strlen(d.ssid) ? d.ssid : "<AP sans SSID>") : "<Station>");
    if (++count >= 20) {
      Serial.println(F("... (limité à 20 premières entrées)"));
      break;
    }
  }
  Serial.printf("Total : %u appareils\n", (unsigned)devices.size());
}

// ─── Gestion commandes Serial ─────────────────────────────────

void handleSerial() {
  if (!Serial.available()) return;
  char cmd = Serial.read();
  while (Serial.available()) Serial.read();

  switch (cmd) {
    case 'h': case 'H':
      Serial.println(F("\n── MENU WiFi Sniffer ─────────────────────"));
      Serial.println(F("[h] Ce menu"));
      Serial.println(F("[s] Statistiques"));
      Serial.println(F("[d] Liste des appareils détectés"));
      Serial.println(F("[c] Toggle hop de canal auto"));
      Serial.println(F("[+] Canal suivant (si hop désactivé)"));
      Serial.println(F("[-] Canal précédent (si hop désactivé)"));
      Serial.println(F("[m] Filtre trames Management seulement"));
      Serial.println(F("[a] Afficher tous types de trames"));
      Serial.println(F("[v] Toggle mode CSV"));
      Serial.println(F("[r] Reset statistiques"));
      break;

    case 's': printStats(); break;
    case 'd': printDeviceList(); break;

    case 'c':
      channelHopEnabled = !channelHopEnabled;
      Serial.printf("[INFO] Hop de canal : %s\n", channelHopEnabled ? "ON" : "OFF");
      break;

    case '+':
      if (!channelHopEnabled) {
        hopChannel();
        Serial.printf("[INFO] Canal : %d\n", currentChannel);
      }
      break;

    case '-':
      if (!channelHopEnabled) {
        currentChannel = ((currentChannel - 2 + 13) % 13) + 1;
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
        Serial.printf("[INFO] Canal : %d\n", currentChannel);
      }
      break;

    case 'm':
      filterEnabled = true;
      filterType    = FRAME_TYPE_MANAGEMENT;
      Serial.println(F("[INFO] Filtre : Management only"));
      break;

    case 'a':
      filterEnabled = false;
      Serial.println(F("[INFO] Filtre : Tous les types"));
      break;

    case 'v':
      csvMode = !csvMode;
      if (csvMode) {
        Serial.println(F("timestamp,type,src_mac,dst_mac,bssid,rssi,channel"));
      } else {
        Serial.println(F("[INFO] Mode CSV désactivé"));
      }
      break;

    case 'r':
      totalPackets = mgmtPackets = dataPackets = ctrlPackets = 0;
      beaconCount  = probeReqCount = probeRespCount = deauthCount = 0;
      devices.clear();
      Serial.println(F("[INFO] Stats réinitialisées."));
      break;

    default:
      Serial.println(F("[?] Commande inconnue. Tape 'h' pour le menu."));
  }
}

// ─── Setup & Loop ─────────────────────────────────────────────

void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.println(F("\n╔══════════════════════════════════════╗"));
  Serial.println(F("║   ESP32 - WiFi Sniffer 802.11        ║"));
  Serial.println(F("╚══════════════════════════════════════╝"));
  Serial.println(F("[WARN] Usage éducatif uniquement !"));
  Serial.println(F("[WARN] Ne pas utiliser sans autorisation."));

  // Init NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    nvs_flash_init();
  }

  // Init WiFi en mode NULL (pas d'AP ni STA)
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_start());

  // Activation du mode promiscuité
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);

  // Filtre : on veut tous les types de paquets
  wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL };
  esp_wifi_set_promiscuous_filter(&filter);

  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

  Serial.println(F("[OK] Sniffer WiFi démarré."));
  Serial.println(F("[OK] Canal 1 — Tape 'h' pour le menu.\n"));
}

void loop() {
  uint32_t now = millis();

  // Hop de canal auto
  if (channelHopEnabled && (now - lastHopTime > CHANNEL_HOP_INTERVAL_MS)) {
    hopChannel();
    lastHopTime = now;
  }

  // Affichage stats auto toutes les DISPLAY_STATS_INTERVAL ms
  if (now - lastStatsTime > DISPLAY_STATS_INTERVAL) {
    lastStatsTime = now;
    Serial.printf("[~] Paquets: %lu | Canal: %d | Appareils: %u\n",
                  totalPackets, currentChannel, (unsigned)devices.size());
  }

  handleSerial();
  delay(10);
}
