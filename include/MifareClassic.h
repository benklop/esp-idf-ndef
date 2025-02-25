#ifndef MifareClassic_h
#define MifareClassic_h

// Comment out next line to remove Mifare Classic and save memory
#define NDEF_SUPPORT_MIFARE_CLASSIC

#ifdef NDEF_SUPPORT_MIFARE_CLASSIC

#define BLOCK_SIZE 16
#define LONG_TLV_SIZE 4
#define SHORT_TLV_SIZE 2

#include <MFRC522.h>
#include <MFRC522Debug.h>
#include <NfcTag.h>

class MifareClassic
{
    public:
        MifareClassic(MFRC522 *nfcShield);
        ~MifareClassic();
        NfcTag read();
        bool write(NdefMessage& ndefMessage);
        bool formatNDEF();
        bool formatMifare();
    private:
        MFRC522* _nfcShield;
        int getBufferSize(int messageLength);
        int getNdefStartIndex(byte *data);
        bool decodeTlv(byte *data, int *messageLength, int *messageStartIndex);
};

#endif
#endif
