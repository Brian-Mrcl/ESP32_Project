/*
 * ============================================================
 *  ESP32 - BLE Scanner & Analyzer
 *  Auteur : Projet Personnel
 * ============================================================
 *
 *  Fonctionnalités :
 *    - Scan BLE passif et actif
 *    - Affichage des appareils : MAC, RSSI, Nom, Services UUID
 *    - Décodage des manufacturer data (Apple iBeacon, Eddystone...)
 *    - Détection des types d'appareils (iBeacon, Eddystone, Unknown)
 *    - Calcul de distance estimée via RSSI
 *    - Tracking des appareils avec historique
 *    - Affichage des Raw Advertisement Data
 *    - Menu interactif via Serial
 *    - Export CSV des appareils détectés
 *
 *  Bibliothèque : Arduino ESP32 BLE (incluse dans le SDK)
 * ============================================================
 */

#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEAddress.h>
#include <map>
#include <string>

// ─── Configuration ────────────────────────────────────────────
#define SCAN_TIME_SEC        5       // Durée d'un scan en secondes
#define SCAN_INTERVAL_MS    10000   // Intervalle entre les scans
#define RSSI_TX_POWER       -59     // Puissance TX de référence à 1m (dBm)
#define RSSI_ENV_FACTOR      2.0f   // Facteur environnemental (2.0 = espace libre)
#define MAX_DEVICES         200     // Max appareils trackés

// ─── Company IDs (Manufacturer Data) ─────────────────────────
#define COMPANY_ID_APPLE    0x004C
#define COMPANY_ID_GOOGLE   0x00E0
#define COMPANY_ID_MICROSOFT 0x0006
#define COMPANY_ID_SAMSUNG  0x0075

// ─── Structures ───────────────────────────────────────────────
struct BLEDeviceInfo {
  std::string address;
  std::string name;
  int8_t      rssi;
  uint32_t    firstSeen;
  uint32_t    lastSeen;
  uint32_t    seenCount;
  bool        isConnectable;
  std::string type;       // iBeacon, Eddystone, Unknown...
  std::string services;   // UUIDs services
  uint16_t    companyId;  // Manufacturer data company ID
  float       distEstimate;

  // iBeacon fields
  uint8_t  ibeaconUUID[16];
  uint16_t ibeaconMajor;
  uint16_t ibeaconMinor;
  int8_t   ibeaconTxPower;
};

// ─── Variables globales ───────────────────────────────────────
static BLEScan*   pBLEScan      = nullptr;
static bool       scanning      = false;
static bool       continuousScan = true;
static bool       verboseMode   = false;
static bool       csvMode       = false;
static bool       activeMode    = false; // Scan actif (envoie des requêtes)

static std::map<std::string, BLEDeviceInfo> bleDevices;
static uint32_t totalScans  = 0;
static uint32_t totalFound  = 0;
static uint32_t lastScanTime = 0;

// ─── Helpers ──────────────────────────────────────────────────

float estimateDistance(int8_t rssi, int8_t txPower = RSSI_TX_POWER) {
  if (rssi == 0) return -1.0f;
  float ratio = (float)(txPower - rssi) / (10.0f * RSSI_ENV_FACTOR);
  return pow(10.0f, ratio);
}

const char* rssiToStrength(int8_t rssi) {
  if (rssi >= -50) return "Excellent";
  if (rssi >= -60) return "Bon";
  if (rssi >= -70) return "Correct";
  if (rssi >= -80) return "Faible";
  return "Très faible";
}

void printHex(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print('0');
    Serial.print(data[i], HEX);
    if (i < len - 1) Serial.print(' ');
  }
}

std::string companyIdToName(uint16_t id) {
  switch (id) {
    case COMPANY_ID_APPLE:     return "Apple";
    case COMPANY_ID_GOOGLE:    return "Google";
    case COMPANY_ID_MICROSOFT: return "Microsoft";
    case COMPANY_ID_SAMSUNG:   return "Samsung";
    case 0x0059:               return "Nordic Semiconductor";
    case 0x0131:               return "Tile";
    case 0x0157:               return "Fitbit";
    default: {
      char buf[10];
      snprintf(buf, sizeof(buf), "0x%04X", id);
      return std::string(buf);
    }
  }
}

// Décodage iBeacon Apple
bool decodeIBeacon(const uint8_t* data, size_t len, BLEDeviceInfo& info) {
  // Format iBeacon : Company ID (0x004C) | Type (0x02) | Len (0x15) | UUID (16) | Major (2) | Minor (2) | TxPower (1)
  if (len < 25) return false;
  if (data[0] != 0x4C || data[1] != 0x00) return false; // Apple
  if (data[2] != 0x02 || data[3] != 0x15) return false; // iBeacon type

  memcpy(info.ibeaconUUID, &data[4], 16);
  info.ibeaconMajor   = (data[20] << 8) | data[21];
  info.ibeaconMinor   = (data[22] << 8) | data[23];
  info.ibeaconTxPower = (int8_t)data[24];
  info.type = "iBeacon";
  info.companyId = COMPANY_ID_APPLE;
  return true;
}

// Décodage Eddystone Google
bool decodeEddystone(const BLEUUID& serviceUUID, const uint8_t* data, size_t len, BLEDeviceInfo& info) {
  // Eddystone service UUID = 0xFEAA
  if (serviceUUID.toString() != "0000feaa-0000-1000-8000-00805f9b34fb") return false;
  if (len < 1) return false;

  uint8_t frameType = data[0];
  switch (frameType) {
    case 0x00: info.type = "Eddystone-UID"; break;
    case 0x10: info.type = "Eddystone-URL"; break;
    case 0x20: info.type = "Eddystone-TLM"; break;
    case 0x30: info.type = "Eddystone-EID"; break;
    default:   info.type = "Eddystone-Unknown"; break;
  }
  return true;
}

// ─── Callback BLE ─────────────────────────────────────────────

class BLEAdvertisedDeviceCallbacks : public BLEAdvertisedDevice::BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) override {
    totalFound++;

    std::string addr = advertisedDevice.getAddress().toString();
    BLEDeviceInfo& info = bleDevices[addr];

    // Mise à jour des infos
    info.address      = addr;
    info.rssi         = advertisedDevice.getRSSI();
    info.lastSeen     = millis();
    info.seenCount++;
    info.isConnectable = advertisedDevice.isConnectable();
    info.distEstimate = estimateDistance(info.rssi);

    if (info.firstSeen == 0) info.firstSeen = millis();

    // Nom de l'appareil
    if (advertisedDevice.haveName()) {
      info.name = advertisedDevice.getName();
    }

    // Services UUIDs
    if (advertisedDevice.haveServiceUUID()) {
      info.services = "";
      for (int i = 0; i < (int)advertisedDevice.getServiceUUIDCount(); i++) {
        if (i > 0) info.services += ", ";
        info.services += advertisedDevice.getServiceUUID(i).toString();
      }
    }

    // Manufacturer Data
    if (advertisedDevice.haveManufacturerData()) {
      std::string mfData = advertisedDevice.getManufacturerData();
      const uint8_t* data = (const uint8_t*)mfData.c_str();
      size_t len = mfData.length();

      if (len >= 2) {
        info.companyId = data[0] | (data[1] << 8);

        // Tentative de décodage iBeacon
        if (!decodeIBeacon(data, len, info)) {
          info.type = "Device [" + companyIdToName(info.companyId) + "]";
        }
      }
    }

    // Service Data (Eddystone)
    if (advertisedDevice.haveServiceData()) {
      std::string svcData = advertisedDevice.getServiceData();
      const uint8_t* data = (const uint8_t*)svcData.c_str();
      BLEUUID svcUUID = advertisedDevice.getServiceDataUUID();
      decodeEddystone(svcUUID, data, svcData.length(), info);
    }

    if (info.type.empty()) info.type = "Unknown";

    // ─── Affichage ──────────────────────────────────────────

    if (csvMode) {
      Serial.printf("%lu,%s,%d,%.2f,%s,%s,%s\n",
                    millis(),
                    info.address.c_str(),
                    info.rssi,
                    info.distEstimate,
                    info.name.empty() ? "<unnamed>" : info.name.c_str(),
                    info.type.c_str(),
                    info.isConnectable ? "yes" : "no");
      return;
    }

    if (!verboseMode) {
      // Mode compact : une ligne par appareil
      Serial.printf("[BLE] %-17s  RSSI:%4ddBm  %-12s  %-20s  %.2fm\n",
                    info.address.c_str(),
                    info.rssi,
                    info.name.empty() ? "<unnamed>" : info.name.substr(0,12).c_str(),
                    info.type.substr(0,20).c_str(),
                    info.distEstimate);
      return;
    }

    // Mode verbose
    Serial.println(F("\n┌── Appareil BLE ──────────────────────────────┐"));
    Serial.printf  ("│ Adresse  : %s\n", info.address.c_str());
    Serial.printf  ("│ Nom      : %s\n", info.name.empty() ? "<inconnu>" : info.name.c_str());
    Serial.printf  ("│ RSSI     : %d dBm (%s)\n", info.rssi, rssiToStrength(info.rssi));
    Serial.printf  ("│ Distance : ~%.2f m\n", info.distEstimate);
    Serial.printf  ("│ Type     : %s\n", info.type.c_str());
    Serial.printf  ("│ Connectable : %s\n", info.isConnectable ? "Oui" : "Non");

    if (!info.services.empty()) {
      Serial.printf("│ Services : %s\n", info.services.c_str());
    }

    if (info.type == "iBeacon") {
      Serial.printf("│ [iBeacon] UUID: ");
      printHex(info.ibeaconUUID, 16);
      Serial.printf("\n│ [iBeacon] Major: %d  Minor: %d  TxPower: %d dBm\n",
                    info.ibeaconMajor, info.ibeaconMinor, info.ibeaconTxPower);
    }

    if (advertisedDevice.haveManufacturerData()) {
      std::string mfData = advertisedDevice.getManufacturerData();
      Serial.print  ("│ MfData   : ");
      printHex((const uint8_t*)mfData.c_str(), min(mfData.length(), (size_t)16));
      if (mfData.length() > 16) Serial.print("...");
      Serial.println();
    }

    Serial.println(F("└──────────────────────────────────────────────┘"));
  }
};

// ─── Fonctions ────────────────────────────────────────────────

void startScan() {
  if (!pBLEScan) return;
  scanning = true;
  totalScans++;
  Serial.printf("[SCAN] Début scan #%lu — Canal: tous — Mode: %s\n",
                totalScans, activeMode ? "Actif" : "Passif");
  pBLEScan->setActiveScan(activeMode);
  pBLEScan->start(SCAN_TIME_SEC, false); // false = non-bloquant
}

void printDeviceList() {
  Serial.println(F("\n── Appareils BLE détectés ───────────────────────────────────────────────────────"));
  Serial.println(F("Adresse           | RSSI  | Dist.  | Vus  | Nom                  | Type"));
  Serial.println(F("------------------|-------|--------|------|----------------------|---------------------"));

  int count = 0;
  for (auto& entry : bleDevices) {
    const BLEDeviceInfo& d = entry.second;
    char nameStr[21] = {0};
    strncpy(nameStr, d.name.empty() ? "<unnamed>" : d.name.c_str(), 20);

    Serial.printf("%-17s | %4ddBm | %5.2fm | %4lu | %-20s | %s\n",
                  d.address.c_str(),
                  d.rssi,
                  d.distEstimate,
                  d.seenCount,
                  nameStr,
                  d.type.c_str());

    if (++count >= 30) {
      Serial.println(F("... (limité à 30)"));
      break;
    }
  }
  Serial.printf("Total : %u appareils uniques\n\n", (unsigned)bleDevices.size());
}

void printStats() {
  Serial.println(F("\n╔═══════════ STATISTIQUES BLE ══════════╗"));
  Serial.printf (  "║ Scans effectués  : %-18lu║\n", totalScans);
  Serial.printf (  "║ Entrées totales  : %-18lu║\n", totalFound);
  Serial.printf (  "║ Appareils uniques: %-18u║\n",  (unsigned)bleDevices.size());
  Serial.printf (  "║ Mode scan        : %-18s║\n",  activeMode ? "Actif" : "Passif");
  Serial.printf (  "║ Mode continu     : %-18s║\n",  continuousScan ? "Oui" : "Non");
  Serial.printf (  "║ Mode verbose     : %-18s║\n",  verboseMode ? "Oui" : "Non");

  // Top 3 signaux les plus forts
  Serial.println(F("║──────────────────────────────────────║"));
  Serial.println(F("║ Top signaux :                        ║"));
  std::vector<std::pair<int8_t, std::string>> rssiList;
  for (auto& e : bleDevices) {
    rssiList.push_back({e.second.rssi, e.second.address});
  }
  std::sort(rssiList.begin(), rssiList.end(), [](auto& a, auto& b){ return a.first > b.first; });
  for (int i = 0; i < min((int)rssiList.size(), 3); i++) {
    Serial.printf(  "║  %s  %4ddBm       ║\n", rssiList[i].second.c_str(), rssiList[i].first);
  }
  Serial.println(F("╚══════════════════════════════════════╝"));
}

void printMenu() {
  Serial.println(F("\n── MENU BLE Scanner ──────────────────────"));
  Serial.println(F("[h] Ce menu"));
  Serial.println(F("[s] Scan unique maintenant"));
  Serial.println(F("[c] Toggle scan continu"));
  Serial.println(F("[a] Toggle mode actif/passif"));
  Serial.println(F("[v] Toggle mode verbose"));
  Serial.println(F("[l] Liste des appareils"));
  Serial.println(F("[t] Statistiques"));
  Serial.println(F("[e] Export CSV"));
  Serial.println(F("[r] Reset"));
}

void handleSerial() {
  if (!Serial.available()) return;
  char cmd = Serial.read();
  while (Serial.available()) Serial.read();

  switch (cmd) {
    case 'h': case 'H': printMenu(); break;
    case 's':
      continuousScan = false;
      startScan();
      break;
    case 'c':
      continuousScan = !continuousScan;
      Serial.printf("[INFO] Scan continu : %s\n", continuousScan ? "ON" : "OFF");
      break;
    case 'a':
      activeMode = !activeMode;
      Serial.printf("[INFO] Mode scan : %s\n", activeMode ? "Actif" : "Passif");
      break;
    case 'v':
      verboseMode = !verboseMode;
      Serial.printf("[INFO] Mode verbose : %s\n", verboseMode ? "ON" : "OFF");
      break;
    case 'l': printDeviceList(); break;
    case 't': printStats(); break;
    case 'e':
      csvMode = true;
      Serial.println(F("timestamp,address,rssi,distance,name,type,connectable"));
      Serial.println(F("[INFO] Mode CSV activé — relance un scan pour exporter."));
      break;
    case 'r':
      bleDevices.clear();
      totalScans = totalFound = 0;
      csvMode = false;
      Serial.println(F("[INFO] Reset effectué."));
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
  Serial.println(F("║    ESP32 - BLE Scanner & Analyzer    ║"));
  Serial.println(F("╚══════════════════════════════════════╝"));

  BLEDevice::init("ESP32-BLE-Scanner");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new BLEAdvertisedDeviceCallbacks(), true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);
  pBLEScan->setActiveScan(false);

  Serial.println(F("[OK] BLE initialisé."));
  Serial.println(F("[OK] Scan passif continu démarré."));
  printMenu();
  Serial.println();

  startScan();
  lastScanTime = millis();
}

void loop() {
  uint32_t now = millis();

  handleSerial();

  // Vérification fin de scan
  if (scanning && !pBLEScan->isScanning()) {
    scanning = false;
    Serial.printf("[SCAN] Scan #%lu terminé. Appareils ce scan : %u total: %u\n",
                  totalScans,
                  pBLEScan->getResults().getCount(),
                  (unsigned)bleDevices.size());
    pBLEScan->clearResults();

    if (csvMode) {
      csvMode = false;
      Serial.println(F("[INFO] Export CSV terminé."));
    }
  }

  // Scan continu
  if (continuousScan && !scanning && (now - lastScanTime > SCAN_INTERVAL_MS)) {
    lastScanTime = now;
    startScan();
  }

  delay(50);
}
