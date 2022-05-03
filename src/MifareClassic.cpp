#include <esp_log.h>
#include "MifareClassic.h"
#ifdef NDEF_SUPPORT_MIFARE_CLASSIC

static const char* LOG_TAG = "Mifare Classic";

MifareClassic::MifareClassic(MFRC522 *nfcShield)
{
  _nfcShield = nfcShield;
}

MifareClassic::~MifareClassic()
{
}

NfcTag MifareClassic::read()
{
    MFRC522::MIFARE_Key key = {{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7}};
    int messageStartIndex = 0;
    int messageLength = 0;
    byte dataSize = BLOCK_SIZE + 2;
    byte data[dataSize];

    // read first block to get message length
    if (_nfcShield->PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 4, &key, &(_nfcShield->uid)) == MFRC522::STATUS_OK)
    {
        if(_nfcShield->MIFARE_Read(4, data, &dataSize) != MFRC522::STATUS_OK)
        {
            ESP_LOGE(LOG_TAG, "Error. Failed read block 4");
            return NfcTag(_nfcShield->uid.uidByte, _nfcShield->uid.size, NfcTag::TYPE_MIFARE_CLASSIC);
        }

        if (!decodeTlv(data, &messageLength, &messageStartIndex))
        {
            ESP_LOGE(LOG_TAG, "Error. Could not decode TLV");
            return NfcTag(_nfcShield->uid.uidByte, _nfcShield->uid.size, NfcTag::TYPE_UNKNOWN); // TODO should the error message go in NfcTag?
        }
    }
    else
    {
        ESP_LOGI(LOG_TAG, "Tag is not NDEF formatted.");
        return NfcTag(_nfcShield->uid.uidByte, _nfcShield->uid.size, NfcTag::TYPE_MIFARE_CLASSIC, false);
    }

    int currentBlock = 4;
    // this should be nested in the message length loop
    int index = 0;
    // Add 2 to allow MFRC522 to add CRC
    int bufferSize = getBufferSize(messageLength) + 2;
    uint8_t buffer[bufferSize];

    ESP_LOGD(LOG_TAG, "Message Length %d", messageLength);
    ESP_LOGD(LOG_TAG, "Buffer Size %d", bufferSize);

    while (index < bufferSize-2)
    {

        // authenticate on every sector
        if (((currentBlock < 128) && (currentBlock % 4 == 0)) || ((currentBlock >= 128) && (currentBlock % 16 == 0)))
        {

            if (_nfcShield->PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, currentBlock, &key, &(_nfcShield->uid)) != MFRC522::STATUS_OK)
            {
                ESP_LOGE(LOG_TAG, "Error. Block Authentication failed for %d", currentBlock);
                // TODO Nicer error handling
                return NfcTag(_nfcShield->uid.uidByte, _nfcShield->uid.size, NfcTag::TYPE_MIFARE_CLASSIC);
            }
        }

        // read the data
        byte readBufferSize = 18;
        if(_nfcShield->MIFARE_Read(currentBlock, &buffer[index], &readBufferSize) == MFRC522::STATUS_OK)
        {
            ESP_LOGD(LOG_TAG, "Block %d:", currentBlock);
            ESP_LOG_BUFFER_HEX_LEVEL(LOG_TAG, &buffer[index], BLOCK_SIZE, ESP_LOG_DEBUG);
        }
        else
        {
            ESP_LOGE(LOG_TAG, "Read failed %d", currentBlock);
            // TODO Nicer error handling
            return NfcTag(_nfcShield->uid.uidByte, _nfcShield->uid.size, NfcTag::TYPE_MIFARE_CLASSIC);
        }

        index += BLOCK_SIZE;
        currentBlock++;

        // skip the trailer block
        if (((currentBlock < 128) && ((currentBlock+1) % 4 == 0)) || ((currentBlock >= 128) && ((currentBlock+1) % 16 == 0)))
        {
            ESP_LOGD(LOG_TAG, "Skipping block %d", currentBlock);
            currentBlock++;
        }
    }

    return NfcTag(_nfcShield->uid.uidByte, _nfcShield->uid.size, NfcTag::TYPE_MIFARE_CLASSIC, &buffer[messageStartIndex], messageLength);
}

int MifareClassic::getBufferSize(int messageLength)
{

    int bufferSize = messageLength;

    // TLV header is 2 or 4 bytes, TLV terminator is 1 byte.
    if (messageLength < 0xFF)
    {
        bufferSize += SHORT_TLV_SIZE + 1;
    }
    else
    {
        bufferSize += LONG_TLV_SIZE + 1;
    }

    // bufferSize needs to be a multiple of BLOCK_SIZE
    if (bufferSize % BLOCK_SIZE != 0)
    {
        bufferSize = ((bufferSize / BLOCK_SIZE) + 1) * BLOCK_SIZE;
    }

    return bufferSize;
}

// skip null tlvs (0x0) before the real message
// technically unlimited null tlvs, but we assume
// T & L of TLV in the first block we read
int MifareClassic::getNdefStartIndex(byte *data)
{

    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        if (data[i] == 0x0)
        {
            // do nothing, skip
        }
        else if (data[i] == 0x3)
        {
            return i;
        }
        else
        {
            ESP_LOGI(LOG_TAG, "Unknown TLV %x", data[i]);
            return -2;
        }
    }

    return -1;
}

// Decode the NDEF data length from the Mifare TLV
// Leading null TLVs (0x0) are skipped
// Assuming T & L of TLV will be in the first block
// messageLength and messageStartIndex written to the parameters
// success or failure status is returned
//
// { 0x3, LENGTH }
// { 0x3, 0xFF, LENGTH, LENGTH }
bool MifareClassic::decodeTlv(byte *data, int *messageLength, int *messageStartIndex)
{
    int i = getNdefStartIndex(data);

    if (i < 0 || data[i] != 0x3)
    {
        ESP_LOGE(LOG_TAG, "Error. Can't decode message length.");
        return false;
    }
    else
    {
        if (data[i+1] == 0xFF)
        {
            *messageLength = ((0xFF & data[i+2]) << 8) | (0xFF & data[i+3]);
            *messageStartIndex = i + LONG_TLV_SIZE;
        }
        else
        {
            *messageLength = data[i+1];
            *messageStartIndex = i + SHORT_TLV_SIZE;
        }
    }

    return true;
}

// Intialized NDEF tag contains one empty NDEF TLV 03 00 FE - AN1304 6.3.1
// We are formatting in read/write mode with a NDEF TLV 03 03 and an empty NDEF record D0 00 00 FE - AN1304 6.3.2
bool MifareClassic::formatNDEF()
{
    MFRC522::MIFARE_Key keya = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
    byte emptyNdefMesg[16] = {0x03, 0x03, 0xD0, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte blockbuffer0[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte blockbuffer1[16] = {0x14, 0x01, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1};
    byte blockbuffer2[16] = {0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1};
    byte blockbuffer3[16] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x78, 0x77, 0x88, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    byte blockbuffer4[16] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0x7F, 0x07, 0x88, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // TODO use UID from method parameters?
    if (_nfcShield->PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 1, &keya, &(_nfcShield->uid)) != MFRC522::STATUS_OK)
    {
        ESP_LOGE(LOG_TAG, "Unable to authenticate block 1 to enable card formatting!");
        return false;
    }

    if (_nfcShield->MIFARE_Write(1, blockbuffer1, 16) != MFRC522::STATUS_OK)
    {
        ESP_LOGE(LOG_TAG, "Unable to format the card for NDEF: Block 1 failed");
        return false;
    }

    if (_nfcShield->MIFARE_Write(2, blockbuffer2, 16) != MFRC522::STATUS_OK)
    {
        ESP_LOGE(LOG_TAG, "Unable to format the card for NDEF: Block 2 failed");
        return false;
    }
    // Write new key A and permissions
    if (_nfcShield->MIFARE_Write(3, blockbuffer3, 16) != MFRC522::STATUS_OK)
    {
        ESP_LOGE(LOG_TAG, "Unable to format the card for NDEF: Block 3 failed");
        return false;
    }
    for (int i=4; i<64; i+=4) {
        if (_nfcShield->PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, i, &keya, &(_nfcShield->uid)) != MFRC522::STATUS_OK)
        {
            ESP_LOGE(LOG_TAG, "Unable to authenticate block %d", i);
            return false;
        }

        if (i == 4)  // special handling for block 4
        {
            if (_nfcShield->MIFARE_Write(i, emptyNdefMesg, 16) != MFRC522::STATUS_OK)
            {
                ESP_LOGE(LOG_TAG, "Unable to write block %d", i);
                return false;
            }
        }
        else
        {
            if (_nfcShield->MIFARE_Write(i, blockbuffer0, 16) != MFRC522::STATUS_OK)
            {
                ESP_LOGE(LOG_TAG, "Unable to write block %d", i);
                return false;
            }
        }
        if (_nfcShield->MIFARE_Write(i+1, blockbuffer0, 16) != MFRC522::STATUS_OK)
        {
            ESP_LOGE(LOG_TAG, "Unable to write block %d", i+1);
            return false;
        }
        if (_nfcShield->MIFARE_Write(i+2, blockbuffer0, 16) != MFRC522::STATUS_OK)
        {
            ESP_LOGE(LOG_TAG, "Unable to write block %d", i+2);
            return false;
        }
        if (_nfcShield->MIFARE_Write(i+3, blockbuffer4, 16) != MFRC522::STATUS_OK)
        {
            ESP_LOGE(LOG_TAG, "Unable to write block %d", i+3);
            return false;
        }
    }
    return true;
}

#define NR_SHORTSECTOR          (32)    // Number of short sectors on Mifare 1K/4K
#define NR_LONGSECTOR           (8)     // Number of long sectors on Mifare 4K
#define NR_BLOCK_OF_SHORTSECTOR (4)     // Number of blocks in a short sector
#define NR_BLOCK_OF_LONGSECTOR  (16)    // Number of blocks in a long sector

// Determine the sector trailer block based on sector number
#define BLOCK_NUMBER_OF_SECTOR_TRAILER(sector) (((sector)<NR_SHORTSECTOR)? \
  ((sector)*NR_BLOCK_OF_SHORTSECTOR + NR_BLOCK_OF_SHORTSECTOR-1):\
  (NR_SHORTSECTOR*NR_BLOCK_OF_SHORTSECTOR + (sector-NR_SHORTSECTOR)*NR_BLOCK_OF_LONGSECTOR + NR_BLOCK_OF_LONGSECTOR-1))

bool MifareClassic::formatMifare()
{

    // The default Mifare Classic key
    MFRC522::MIFARE_Key KEY_DEFAULT_KEYAB = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
    byte emptyBlock[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte authBlock[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


    uint8_t idx = 0;
    uint8_t numOfSector = 16;                         // Assume Mifare Classic 1K for now (16 4-block sectors)

    for (idx = 0; idx < numOfSector; idx++)
    {
        // Step 1: Authenticate the current sector using key B 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
        if (_nfcShield->PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, BLOCK_NUMBER_OF_SECTOR_TRAILER(idx), &KEY_DEFAULT_KEYAB, &(_nfcShield->uid)) != MFRC522::STATUS_OK)
        {
            ESP_LOGE(LOG_TAG, "Authentication failed for sector %d", idx);
            return false;
        }

        // Step 2: Write to the other blocks
        if (idx == 0)
        {
            if (_nfcShield->MIFARE_Write((BLOCK_NUMBER_OF_SECTOR_TRAILER(idx)) - 2, emptyBlock, 16) != MFRC522::STATUS_OK)
            {
                ESP_LOGE(LOG_TAG, "Unable to write to sector %d", idx);
            }
        }
        else
        {
            // this block has not to be overwritten for block 0. It contains Tag id and other unique data.
            if (_nfcShield->MIFARE_Write((BLOCK_NUMBER_OF_SECTOR_TRAILER(idx)) - 3, emptyBlock, 16) != MFRC522::STATUS_OK)
            {
                ESP_LOGE(LOG_TAG, "Unable to write to sector %d", idx);
            }
            if (_nfcShield->MIFARE_Write((BLOCK_NUMBER_OF_SECTOR_TRAILER(idx)) - 2, emptyBlock, 16) != MFRC522::STATUS_OK)
            {
                ESP_LOGE(LOG_TAG, "Unable to write to sector %d", idx);
            }
        }

        if (_nfcShield->MIFARE_Write((BLOCK_NUMBER_OF_SECTOR_TRAILER(idx)) - 1, emptyBlock, 16) != MFRC522::STATUS_OK)
        {
            ESP_LOGE(LOG_TAG, "Unable to write to sector %d", idx);
        }

        // Write the trailer block
        if (_nfcShield->MIFARE_Write((BLOCK_NUMBER_OF_SECTOR_TRAILER(idx)), authBlock, 16) != MFRC522::STATUS_OK)
        {
            ESP_LOGE(LOG_TAG, "Unable to write trailer byte of sector %d", idx);
        }
    }
    return true;
}

bool MifareClassic::write(NdefMessage& m)
{

    uint8_t encoded[m.getEncodedSize()];
    m.encode(encoded);

    uint8_t buffer[getBufferSize(sizeof(encoded))];
    memset(buffer, 0, sizeof(buffer));

    ESP_LOGD(LOG_TAG, "sizeof(encoded) %d", sizeof(encoded));
    ESP_LOGD(LOG_TAG, "sizeof(buffer) %d", sizeof(buffer));

    if (sizeof(encoded) < 0xFF)
    {
        buffer[0] = 0x3;
        buffer[1] = sizeof(encoded);
        memcpy(&buffer[2], encoded, sizeof(encoded));
        buffer[2+sizeof(encoded)] = 0xFE; // terminator
    }
    else
    {
        buffer[0] = 0x3;
        buffer[1] = 0xFF;
        buffer[2] = ((sizeof(encoded) >> 8) & 0xFF);
        buffer[3] = (sizeof(encoded) & 0xFF);
        memcpy(&buffer[4], encoded, sizeof(encoded));
        buffer[4+sizeof(encoded)] = 0xFE; // terminator
    }

    // Write to tag
    unsigned int index = 0;
    byte currentBlock = 4;
    MFRC522::MIFARE_Key key = {{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7}};

    while (index < sizeof(buffer))
    {

        if (((currentBlock < 128) && (currentBlock % 4 == 0)) || ((currentBlock >= 128) && (currentBlock % 16 == 0)))
        {
            MFRC522::StatusCode status =_nfcShield->PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, currentBlock, &key, &(_nfcShield->uid));
            if (status != MFRC522::STATUS_OK)
            {
                ESP_LOGE(LOG_TAG, "Error. Block authentication failed for block %d: %s", currentBlock, MFRC522Debug::GetStatusCodeName(status));
                return false;
            }
        }

        if (_nfcShield->MIFARE_Write(currentBlock, &buffer[index], BLOCK_SIZE) != MFRC522::STATUS_OK)
        {
            ESP_LOGE(LOG_TAG, "Write failed %d", currentBlock);
            return false;
        }

        
        ESP_LOGD(LOG_TAG, "Wrote block %d:", currentBlock)
        ESP_LOG_BUFFER_HEX_LEVEL(LOG_TAG, &buffer[index], BLOCK_SIZE, ESP_LOG_DEBUG);

        index += BLOCK_SIZE;
        currentBlock++;

        if (((currentBlock < 128) && ((currentBlock+1) % 4 == 0)) || ((currentBlock >= 128) && ((currentBlock+1) % 16 == 0)))
        {
            // can't write to trailer block
            ESP_LOGD(LOG_TAG, "Skipping block %d", currentBlock);
            currentBlock++;
        }

    }

    return true;
}
#endif
