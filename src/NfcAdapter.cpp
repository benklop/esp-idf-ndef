#include <esp_log.h>
#include "NfcAdapter.h"

static const char* LOG_TAG = "NFC Adapter";

NfcAdapter::NfcAdapter(MFRC522 *interface)
{
    shield = interface;
}

NfcAdapter::~NfcAdapter(void)
{
}

void NfcAdapter::begin()
{
  shield->PCD_DumpVersionToSerial();
}

bool NfcAdapter::tagPresent()
{
    // If tag has already been authenticated nothing else will work until we stop crypto (shouldn't hurt)
    shield->PCD_StopCrypto1();

    if(!(shield->PICC_IsNewCardPresent() && shield->PICC_ReadCardSerial()))
    {
        return false;
    }

    MFRC522::PICC_Type piccType = shield->PICC_GetType(shield->uid.sak);
    return ((piccType == MFRC522::PICC_TYPE_MIFARE_1K) || (piccType == MFRC522::PICC_TYPE_MIFARE_UL));
}

bool NfcAdapter::erase()
{
    NdefMessage message = NdefMessage();
    message.addEmptyRecord();
    return write(message);
}

bool NfcAdapter::format()
{
#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if(shield->PICC_GetType(shield->uid.sak) == MFRC522::PICC_TYPE_MIFARE_1K)
    {
        MifareClassic mifareClassic = MifareClassic(shield);
        return mifareClassic.formatNDEF();
    }
    else
#endif
    if(shield->PICC_GetType(shield->uid.sak) == MFRC522::PICC_TYPE_MIFARE_UL)
    {
        ESP_LOGD(LOG_TAG, "No need for formating a UL");
        return true;
    }
    else
    {
        ESP_LOGD(LOG_TAG, "Unsupported Tag.");
        return false;
    }
}

bool NfcAdapter::clean()
{
    NfcTag::TagType type = guessTagType();

#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if (type == NfcTag::TYPE_MIFARE_CLASSIC)
    {
        ESP_LOGD(LOG_TAG, "Cleaning Mifare Classic");
        MifareClassic mifareClassic = MifareClassic(shield);
        return mifareClassic.formatMifare();
    }
    else
#endif
    if (type == NfcTag::TYPE_2)
    {
        ESP_LOGD(LOG_TAG, "Cleaning Mifare Ultralight");
        MifareUltralight ultralight = MifareUltralight(shield);
        return ultralight.clean();
    }
    else
    {
        ESP_LOGI(LOG_TAG, "No driver for card type %d", type);
        return false;
    }

}

NfcTag NfcAdapter::read()
{
    uint8_t type = guessTagType();

#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if (type == NfcTag::TYPE_MIFARE_CLASSIC)
    {
        ESP_LOGD(LOG_TAG, "Reading Mifare Classic");
        MifareClassic mifareClassic = MifareClassic(shield);
        return mifareClassic.read();
    }
    else
#endif
    if (type == NfcTag::TYPE_2)
    {
        ESP_LOGD(LOG_TAG, "Reading Mifare Ultralight");
        MifareUltralight ultralight = MifareUltralight(shield);
        return ultralight.read();
    }
    else if (type == NfcTag::TYPE_UNKNOWN)
    {
        ESP_LOGI(LOG_TAG, "Can not determine tag type");
        return NfcTag(shield->uid.uidByte, shield->uid.size, NfcTag::TYPE_UNKNOWN);
    }
    else
    {
        ESP_LOGI(LOG_TAG, "No driver for card type %d", type);
        // TODO should set type here
        return NfcTag(shield->uid.uidByte, shield->uid.size, NfcTag::TYPE_UNKNOWN);
    }

}

bool NfcAdapter::write(NdefMessage& ndefMessage)
{
    uint8_t type = guessTagType();

#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if (type == NfcTag::TYPE_MIFARE_CLASSIC)
    {
        ESP_LOGD(LOG_TAG, "Writing Mifare Classic");
        MifareClassic mifareClassic = MifareClassic(shield);
        return mifareClassic.write(ndefMessage);
    }
    else
#endif
    if (type == NfcTag::TYPE_2)
    {
        ESP_LOGD(LOG_TAG, "Writing Mifare Ultralight");
        MifareUltralight mifareUltralight = MifareUltralight(shield);
        return mifareUltralight.write(ndefMessage);
    }
    else if (type == NfcTag::TYPE_UNKNOWN)
    {
        ESP_LOGI(LOG_TAG, "Can not determine tag type");
        return false;
    }
    else
    {
        ESP_LOGD(LOG_TAG, "No driver for card type %d", type);
        return false;
    }
}

// Current tag will not be "visible" until removed from the RFID field
void NfcAdapter::haltTag() {
    shield->PICC_HaltA();
    shield->PCD_StopCrypto1();
}

NfcTag::TagType NfcAdapter::guessTagType()
{

    MFRC522::PICC_Type piccType = shield->PICC_GetType(shield->uid.sak);

    if (piccType == MFRC522::PICC_TYPE_MIFARE_1K)
    {
        return NfcTag::TYPE_MIFARE_CLASSIC;
    } 
    else if (piccType == MFRC522::PICC_TYPE_MIFARE_UL)
    {
        return NfcTag::TYPE_2;
    }
    else
    {
        return NfcTag::TYPE_UNKNOWN;
    }
}
