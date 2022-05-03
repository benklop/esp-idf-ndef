#include <cstdlib>
#include <string>
#include <esp_log.h>
#include "NdefRecord.h"

static const char* LOG_TAG = "NDef Record";

NdefRecord::NdefRecord()
{
    _tnf = NdefRecord::TNF_EMPTY;
    _typeLength = 0;
    _payloadLength = 0;
    _idLength = 0;
    _type = NULL;
    _payload = NULL;
    _id = NULL;
}

NdefRecord::NdefRecord(const NdefRecord& rhs)
{
    _tnf = rhs._tnf;
    _typeLength = rhs._typeLength;
    _payloadLength = rhs._payloadLength;
    _idLength = rhs._idLength;
    _type = NULL;
    _payload = NULL;
    _id = NULL;

    if (_typeLength)
    {
        _type = (byte*)malloc(_typeLength);
        memcpy(_type, rhs._type, _typeLength);
    }

    if (_payloadLength)
    {
        _payload = (byte*)malloc(_payloadLength);
        memcpy(_payload, rhs._payload, _payloadLength);
    }

    if (_idLength)
    {
        _id = (byte*)malloc(_idLength);
        memcpy(_id, rhs._id, _idLength);
    }

}

NdefRecord::~NdefRecord()
{
    free(_type);
    free(_payload);
    free(_id);
}

NdefRecord& NdefRecord::operator=(const NdefRecord& rhs)
{
    ESP_LOGD(LOG_TAG, "NdefRecord ASSIGN");

    if (this != &rhs)
    {
        // free existing
        free(_type);
        free(_payload);
        free(_id);

        _tnf = rhs._tnf;
        _typeLength = rhs._typeLength;
        _payloadLength = rhs._payloadLength;
        _idLength = rhs._idLength;

        if (_typeLength)
        {
            _type = (byte*)malloc(_typeLength);
            if(_type)
                memcpy(_type, rhs._type, _typeLength);
            else
                ESP_LOGE(LOG_TAG, "type malloc failed");
        }
        else
        {
            _type = NULL;
        }

        if (_payloadLength)
        {
            _payload = (byte*)malloc(_payloadLength);
            if(_payload)
                memcpy(_payload, rhs._payload, _payloadLength);
            else
                ESP_LOGE(LOG_TAG, "payload malloc failed");
        }
        else
        {
            _payload = NULL;
        }

        if (_idLength)
        {
            _id = (byte*)malloc(_idLength);
            if(_id)
                memcpy(_id, rhs._id, _idLength);
            else
                ESP_LOGE(LOG_TAG, "id malloc failed");
        }
        else
        {
            _id = NULL;
        }
    }
    return *this;
}

// size of records in bytes
unsigned int NdefRecord::getEncodedSize()
{
    unsigned int size = 2; // tnf + typeLength
    if (_payloadLength > 0xFF)
    {
        size += 4;
    }
    else
    {
        size += 1;
    }

    if (_idLength)
    {
        size += 1;
    }

    size += (_typeLength + _payloadLength + _idLength);

    return size;
}

void NdefRecord::encode(byte *data, bool firstRecord, bool lastRecord)
{
    // assert data > getEncodedSize()

    uint8_t* data_ptr = &data[0];

    *data_ptr = _getTnfByte(firstRecord, lastRecord);
    data_ptr += 1;

    *data_ptr = _typeLength;
    data_ptr += 1;

    if (_payloadLength <= 0xFF) {  // short record
        *data_ptr = _payloadLength;
        data_ptr += 1;
    } else { // long format
        // 4 bytes but we store length as an int
        data_ptr[0] = 0x0; // (_payloadLength >> 24) & 0xFF;
        data_ptr[1] = 0x0; // (_payloadLength >> 16) & 0xFF;
        data_ptr[2] = (_payloadLength >> 8) & 0xFF;
        data_ptr[3] = _payloadLength & 0xFF;
        data_ptr += 4;
    }

    if (_idLength)
    {
        *data_ptr = _idLength;
        data_ptr += 1;
    }

    //Serial.println(2);
    memcpy(data_ptr, _type, _typeLength);
    data_ptr += _typeLength;

    if (_idLength)
    {
        memcpy(data_ptr, _id, _idLength);
        data_ptr += _idLength;
    }
    
    memcpy(data_ptr, _payload, _payloadLength);
    data_ptr += _payloadLength;
}

byte NdefRecord::_getTnfByte(bool firstRecord, bool lastRecord)
{
    int value = _tnf;

    if (firstRecord) { // mb
        value = value | 0x80;
    }

    if (lastRecord) { //
        value = value | 0x40;
    }

    // chunked flag is always false for now
    // if (cf) {
    //     value = value | 0x20;
    // }

    if (_payloadLength <= 0xFF) {
        value = value | 0x10;
    }

    if (_idLength) {
        value = value | 0x8;
    }

    return value;
}

NdefRecord::TNF NdefRecord::getTnf()
{
    return _tnf;
}

void NdefRecord::setTnf(NdefRecord::TNF tnf)
{
    _tnf = tnf;
}

unsigned int NdefRecord::getTypeLength()
{
    return _typeLength;
}

unsigned int NdefRecord::getPayloadLength()
{
    return _payloadLength;
}

unsigned int NdefRecord::getIdLength()
{
    return _idLength;
}

const byte* NdefRecord::getType()
{
    return _type;
}

void NdefRecord::setType(const byte *type, const unsigned int numBytes)
{
    free(_type);

    _type = (uint8_t*)malloc(numBytes);
    memcpy(_type, type, numBytes);
    _typeLength = numBytes;
}

const byte* NdefRecord::getPayload()
{
    return _payload;
}

void NdefRecord::setPayload(const byte *payload, const int numBytes)
{
    free(_payload);

    _payload = (byte*)malloc(numBytes);
    memcpy(_payload, payload, numBytes);
    _payloadLength = numBytes;
}

void NdefRecord::setPayload(const byte *header, const int headerLength, const byte *payload, const int payloadLength)
{
    free(_payload);

    _payload = (byte*)malloc(headerLength+payloadLength);
    memcpy(_payload, header, headerLength);
    memcpy(_payload+headerLength, payload, payloadLength);
    _payloadLength = headerLength+payloadLength;
}

const byte* NdefRecord::getId()
{
    return _id;
}

void NdefRecord::setId(const byte *id, const unsigned int numBytes)
{
    free(_id);

    _id = (byte*)malloc(numBytes);
    memcpy(_id, id, numBytes);
    _idLength = numBytes;
}

void NdefRecord::print()
{
    ESP_LOGI(LOG_TAG, "  NDEF Record");
    std::string meaning;
    switch (_tnf) {
    case TNF_EMPTY:
        meaning = "Empty";
        break;
    case TNF_WELL_KNOWN:
        meaning = "Well Known";
        break;
    case TNF_MIME_MEDIA:
        meaning = "Mime Media";
        break;
    case TNF_ABSOLUTE_URI:
        meaning = "Absolute URI";
        break;
    case TNF_EXTERNAL_TYPE:
        meaning = "External";
        break;
    case TNF_UNKNOWN:
        meaning = "Unknown";
        break;
    case TNF_UNCHANGED:
        meaning = "Unchanged";
        break;
    case TNF_RESERVED:
        meaning = "Reserved";
        break;
    }
    ESP_LOGI(LOG_TAG, "    TNF 0x%x, %s", _tnf, meaning);

    ESP_LOGI(LOG_TAG, "    Type Length 0x%x %d", _typeLength, _typeLength);
    ESP_LOGI(LOG_TAG, "    Payload Length 0x%x %d", _payloadLength, _payloadLength);
    if (_idLength)
    {
        ESP_LOGI(LOG_TAG, "    Id Length 0x%x", _idLength);
    }
    ESP_LOGI(LOG_TAG, "    Type:");
    ESP_LOG_BUFFER_HEX(LOG_TAG, _type, _typeLength);
    ESP_LOGI(LOG_TAG, "    Payload:");
    ESP_LOG_BUFFER_HEXDUMP(LOG_TAG, _payload, _payloadLength, ESP_LOG_INFO);
    if (_idLength)
    {
        ESP_LOGI(LOG_TAG, "    Id: ");
        ESP_LOG_BUFFER_HEX(LOG_TAG, _id, _idLength);
    }
    ESP_LOGI(LOG_TAG, "    Record is %d bytes", getEncodedSize());

}
