/*
 * ============================================================
 *  ESP32 - RFID MIFARE 1K Cloner & Reader
 *  Module : RC522
 *  Auteur : Projet Personnel
 * ============================================================
 *
 *  Pinout ESP32 -> RC522 :
 *    GPIO 4  -> SCK
 *    GPIO 5  -> MISO
 *    GPIO 6  -> MOSI
 *    GPIO 7  -> SDA (SS)
 *    GPIO 8  -> RST
 *    3.3V    -> VCC
 *    GND     -> GND
 *
 *  Fonctionnalités :
 *    - Lecture UID + type de carte
 *    - Dump complet des 64 blocs MIFARE 1K
 *    - Clonage d'UID (nécessite carte Magic / UID modifiable)
 *    - Écriture de données sur des secteurs
 *    - Menu interactif via Serial Monitor
 * ============================================================
 */

#include <SPI.h>
#include <MFRC522.h>

// ─── Pins ────────────────────────────────────────────────────
#define SS_PIN   7
#define RST_PIN  8
#define PIN_SCK  4
#define PIN_MISO 5
#define PIN_MOSI 6

// ─── Objet RFID ──────────────────────────────────────────────
MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key keyDefault;

// ─── UID cible à cloner (modifie ici) ────────────────────────
byte targetUID[] = {0xBE, 0x22, 0xAA, 0x7B};
byte targetUIDSize = 4;

// ─── Mode actuel ─────────────────────────────────────────────
enum Mode { MODE_MENU, MODE_READ, MODE_DUMP, MODE_CLONE, MODE_WRITE };
Mode currentMode = MODE_MENU;

// ─────────────────────────────────────────────────────────────

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);

  SPI.begin(PIN_SCK, PIN_MISO, PIN_MOSI, SS_PIN);
  mfrc522.PCD_Init();
  delay(100);

  // Clé par défaut : 6x 0xFF
  for (byte i = 0; i < 6; i++) keyDefault.keyByte[i] = 0xFF;

  Serial.println();
  Serial.println(F("╔══════════════════════════════════════╗"));
  Serial.println(F("║   ESP32 RFID RC522 - Cloner/Reader   ║"));
  Serial.println(F("╚══════════════════════════════════════╝"));

  byte version = mfrc522.PCD_ReadRegister(MFRC522::VersionReg);
  Serial.print(F("[INFO] Version RC522 : 0x"));
  Serial.println(version, HEX);

  if (version == 0x00 || version == 0xFF) {
    Serial.println(F("[ERREUR] RC522 non détecté ! Vérifie le câblage."));
  } else {
    Serial.println(F("[OK] RC522 initialisé."));
  }

  printMenu();
}

// ─────────────────────────────────────────────────────────────

void loop() {
  // Lecture des commandes Serial
  if (Serial.available()) {
    char cmd = Serial.read();
    while (Serial.available()) Serial.read(); // Vider le buffer
    handleCommand(cmd);
    return;
  }

  // En mode MENU, on attend juste la commande
  if (currentMode == MODE_MENU) return;

  // Attente d'une carte
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    delay(200);
    return;
  }

  Serial.println();
  Serial.println(F("──── Carte détectée ────"));
  printCardInfo();

  switch (currentMode) {
    case MODE_READ:  doReadMode();  break;
    case MODE_DUMP:  doDumpMode();  break;
    case MODE_CLONE: doCloneMode(); break;
    default: break;
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  Serial.println(F("────────────────────────"));
  printMenu();
  currentMode = MODE_MENU;
}

// ─── Menu ─────────────────────────────────────────────────────

void printMenu() {
  Serial.println();
  Serial.println(F("┌── MENU ──────────────────────────────┐"));
  Serial.println(F("│  [1] Lire UID d'une carte             │"));
  Serial.println(F("│  [2] Dump complet (64 blocs)          │"));
  Serial.println(F("│  [3] Cloner UID vers carte Magic      │"));
  Serial.println(F("│  [4] Afficher UID cible configuré     │"));
  Serial.println(F("│  [h] Afficher ce menu                 │"));
  Serial.println(F("└───────────────────────────────────────┘"));
  Serial.println(F("Entrez une commande :"));
}

void handleCommand(char cmd) {
  switch (cmd) {
    case '1':
      currentMode = MODE_READ;
      Serial.println(F("[>] Mode : Lecture UID — Approche une carte..."));
      break;
    case '2':
      currentMode = MODE_DUMP;
      Serial.println(F("[>] Mode : Dump complet — Approche une carte..."));
      break;
    case '3':
      currentMode = MODE_CLONE;
      Serial.print(F("[>] Mode : Clone UID -> "));
      printUID(targetUID, targetUIDSize);
      Serial.println(F(" — Approche une carte Magic..."));
      break;
    case '4':
      Serial.print(F("[INFO] UID cible : "));
      printUID(targetUID, targetUIDSize);
      Serial.println();
      printMenu();
      break;
    case 'h':
    case 'H':
      printMenu();
      break;
    default:
      Serial.println(F("[?] Commande inconnue. Tape 'h' pour le menu."));
      break;
  }
}

// ─── Infos carte ──────────────────────────────────────────────

void printCardInfo() {
  Serial.print(F("UID      : "));
  printUID(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();

  Serial.print(F("SAK      : 0x"));
  Serial.println(mfrc522.uid.sak, HEX);

  MFRC522::PICC_Type type = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.print(F("Type     : "));
  Serial.println(mfrc522.PICC_GetTypeName(type));
}

void printUID(byte* uid, byte size) {
  for (byte i = 0; i < size; i++) {
    if (uid[i] < 0x10) Serial.print('0');
    Serial.print(uid[i], HEX);
    if (i < size - 1) Serial.print(':');
  }
}

// ─── Mode 1 : Lecture simple ──────────────────────────────────

void doReadMode() {
  MFRC522::PICC_Type type = mfrc522.PICC_GetType(mfrc522.uid.sak);
  if (type != MFRC522::PICC_TYPE_MIFARE_1K &&
      type != MFRC522::PICC_TYPE_MIFARE_MINI &&
      type != MFRC522::PICC_TYPE_MIFARE_4K) {
    Serial.println(F("[WARN] Type non MIFARE, lecture des blocs ignorée."));
    return;
  }

  Serial.println(F("[OK] Carte MIFARE détectée."));
}

// ─── Mode 2 : Dump complet ────────────────────────────────────

void doDumpMode() {
  MFRC522::PICC_Type type = mfrc522.PICC_GetType(mfrc522.uid.sak);

  if (type != MFRC522::PICC_TYPE_MIFARE_1K) {
    Serial.println(F("[WARN] Dump optimisé pour MIFARE 1K (16 secteurs x 4 blocs)."));
  }

  Serial.println(F("\n=== DUMP MIFARE 1K ==="));
  Serial.println(F("Secteur | Bloc | Données (HEX)                   | ASCII"));
  Serial.println(F("--------|------|----------------------------------|------"));

  for (byte sector = 0; sector < 16; sector++) {
    for (byte blockOffset = 0; blockOffset < 4; blockOffset++) {
      byte blockAddr = sector * 4 + blockOffset;

      // Authentification au début de chaque secteur
      if (blockOffset == 0) {
        MFRC522::StatusCode status = mfrc522.PCD_Authenticate(
          MFRC522::PICC_CMD_MF_AUTH_KEY_A,
          sector * 4 + 3,
          &keyDefault,
          &(mfrc522.uid)
        );

        if (status != MFRC522::STATUS_OK) {
          Serial.print(F("  "));
          if (sector < 10) Serial.print(' ');
          Serial.print(sector);
          Serial.print(F("     | "));
          if (blockAddr < 10) Serial.print(' ');
          Serial.print(blockAddr);
          Serial.print(F("   | AUTH FAILED ("));
          Serial.print(mfrc522.GetStatusCodeName(status));
          Serial.println(F(")"));
          break; // Passer au secteur suivant
        }
      }

      byte buffer[18];
      byte size = sizeof(buffer);
      MFRC522::StatusCode status = mfrc522.MIFARE_Read(blockAddr, buffer, &size);

      if (status != MFRC522::STATUS_OK) {
        Serial.print(F("  "));
        if (sector < 10) Serial.print(' ');
        Serial.print(sector);
        Serial.print(F("     | "));
        if (blockAddr < 10) Serial.print(' ');
        Serial.print(blockAddr);
        Serial.println(F("   | READ FAILED"));
        continue;
      }

      // Affichage formaté
      if (sector < 10) Serial.print(' ');
      Serial.print(sector);
      Serial.print(F("      | "));
      if (blockAddr < 10) Serial.print(' ');
      Serial.print(blockAddr);
      Serial.print(F("   | "));

      for (byte i = 0; i < 16; i++) {
        if (buffer[i] < 0x10) Serial.print('0');
        Serial.print(buffer[i], HEX);
        Serial.print(' ');
      }

      Serial.print(F("| "));
      for (byte i = 0; i < 16; i++) {
        char c = (char)buffer[i];
        Serial.print(isPrintable(c) ? c : '.');
      }

      // Marquage des blocs spéciaux
      if (blockAddr == 0) Serial.print(F("  <- Bloc fabricant (UID)"));
      if (blockOffset == 3) Serial.print(F("  <- Bloc trailer"));

      Serial.println();
    }
  }

  Serial.println(F("=== FIN DU DUMP ==="));
}

// ─── Mode 3 : Clone UID ───────────────────────────────────────

void doCloneMode() {
  MFRC522::PICC_Type type = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.print(F("[INFO] Type détecté : "));
  Serial.println(mfrc522.PICC_GetTypeName(type));

  // Vérification que c'est bien une carte Magic / UID modifiable
  // Les cartes Magic MIFARE ont le SAK = 0x08 (1K) mais acceptent l'écriture du bloc 0
  if (writeUID(targetUID, targetUIDSize)) {
    Serial.println(F("[✓] Clone réussi !"));
    Serial.print(F("[✓] Nouvel UID : "));
    printUID(targetUID, targetUIDSize);
    Serial.println();
  } else {
    Serial.println(F("[✗] Échec du clone."));
    Serial.println(F("[!] Vérifications :"));
    Serial.println(F("    - Carte de type 'Magic' / UID modifiable"));
    Serial.println(F("    - Clé A du secteur 0 = FF FF FF FF FF FF"));
    Serial.println(F("    - Bien maintenir la carte pendant l'écriture"));
  }
}

bool writeUID(byte* uid, byte uidLen) {
  // Authentification secteur 0
  MFRC522::StatusCode status = mfrc522.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A,
    0,
    &keyDefault,
    &(mfrc522.uid)
  );

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("[ERR] Auth secteur 0 : "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }

  // Lecture du bloc 0 actuel
  byte buffer[18];
  byte bufferSize = sizeof(buffer);
  status = mfrc522.MIFARE_Read(0, buffer, &bufferSize);

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("[ERR] Lecture bloc 0 : "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }

  Serial.print(F("[INFO] Bloc 0 actuel : "));
  for (byte i = 0; i < 16; i++) {
    if (buffer[i] < 0x10) Serial.print('0');
    Serial.print(buffer[i], HEX);
    Serial.print(' ');
  }
  Serial.println();

  // Remplacement UID + recalcul BCC
  for (byte i = 0; i < uidLen && i < 4; i++) buffer[i] = uid[i];

  // BCC = XOR de tous les bytes de l'UID
  buffer[4] = 0;
  for (byte i = 0; i < uidLen; i++) buffer[4] ^= uid[i];

  Serial.print(F("[INFO] Bloc 0 nouveau : "));
  for (byte i = 0; i < 16; i++) {
    if (buffer[i] < 0x10) Serial.print('0');
    Serial.print(buffer[i], HEX);
    Serial.print(' ');
  }
  Serial.println();

  // Écriture du bloc 0
  status = mfrc522.MIFARE_Write(0, buffer, 16);

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("[ERR] Écriture bloc 0 : "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    Serial.println(F("[!] La carte n'est probablement pas une carte Magic."));
    return false;
  }

  // Vérification post-écriture
  bufferSize = sizeof(buffer);
  status = mfrc522.MIFARE_Read(0, buffer, &bufferSize);
  if (status == MFRC522::STATUS_OK) {
    Serial.print(F("[INFO] Vérification bloc 0 : "));
    for (byte i = 0; i < 16; i++) {
      if (buffer[i] < 0x10) Serial.print('0');
      Serial.print(buffer[i], HEX);
      Serial.print(' ');
    }
    Serial.println();

    // Vérification de l'UID écrit
    bool match = true;
    for (byte i = 0; i < uidLen; i++) {
      if (buffer[i] != uid[i]) { match = false; break; }
    }
    if (match) {
      Serial.println(F("[✓] Vérification UID : OK"));
    } else {
      Serial.println(F("[✗] Vérification UID : MISMATCH !"));
      return false;
    }
  }

  return true;
}
