
#include <esp_log.h>
#include "NfcTag.h"

static const char* LOG_TAG = "NFC Tag";

NfcTag::NfcTag(byte *uid, uint8_t  uidLength, TagType tagType)
{
    _uid = uid;
    _uidLength = uidLength;
    _tagType = tagType;
    _ndefMessage = (NdefMessage*)NULL;
    _isFormatted = false;
}

NfcTag::NfcTag(byte *uid, uint8_t  uidLength, TagType tagType, bool isFormatted)
{
    _uid = uid;
    _uidLength = uidLength;
    _tagType = tagType;
    _ndefMessage = (NdefMessage*)NULL;
    _isFormatted = isFormatted;
}

NfcTag::NfcTag(byte *uid, uint8_t  uidLength, TagType tagType, NdefMessage& ndefMessage)
{
    _uid = uid;
    _uidLength = uidLength;
    _tagType = tagType;
    _ndefMessage = new NdefMessage(ndefMessage);
    _isFormatted = true; // If it has a message it's formatted
}

NfcTag::NfcTag(byte *uid, uint8_t uidLength, TagType tagType, const byte *ndefData, const uint16_t ndefDataLength)
{
    _uid = uid;
    _uidLength = uidLength;
    _tagType = tagType;
    _ndefMessage = new NdefMessage(ndefData, ndefDataLength);
    _isFormatted = true; // If it has a message it's formatted
}

NfcTag::~NfcTag()
{
    delete _ndefMessage;
}

NfcTag& NfcTag::operator=(const NfcTag& rhs)
{
    if (this != &rhs)
    {
        delete _ndefMessage;
        _uid = rhs._uid;
        _uidLength = rhs._uidLength;
        _tagType = rhs._tagType;
        _ndefMessage = new NdefMessage(*rhs._ndefMessage);
    }
    return *this;
}

uint8_t NfcTag::getUidLength()
{
    return _uidLength;
}

void NfcTag::getUid(byte *uid, uint8_t *uidLength)
{
    memcpy(uid, _uid, _uidLength < *uidLength ? _uidLength : *uidLength);
    *uidLength = _uidLength;
}

NfcTag::TagType NfcTag::getTagType()
{
    return _tagType;
}

bool NfcTag::hasNdefMessage()
{
    return (_ndefMessage != NULL);
}

NdefMessage NfcTag::getNdefMessage()
{
    return *_ndefMessage;
}

bool NfcTag::isFormatted()
{
    return _isFormatted;
}

void NfcTag::print()
{
    ESP_LOGI(LOG_TAG, "NFC Tag - %d", _tagType);

    if (_ndefMessage == NULL)
    {
        ESP_LOGI(LOG_TAG, "No NDEF Message");
    }
    else
    {
        _ndefMessage->print();
    }
}
