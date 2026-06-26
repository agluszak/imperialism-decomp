#pragma once

#include "game/TEventHandler.h"
#include "game/mfc.h"

class TStream;

// VTABLE: IMPERIALISM 0x0065c030
class TMultiplayerMgr : public TEventHandler {
public:
  int field20[8];
  int field40;
  unsigned char padding44[0x6c - 0x44];
  int field6c;
  int field70;
  CString field74;
  CString field78[7];
  CString field94[7];
  CString fieldb0;
  CString fieldb4;
  CString fieldb8;
  unsigned char paddingbc[0xd8 - 0xbc];
  int fieldd8;
  unsigned char paddingdc[0xf4 - 0xdc];
  unsigned char fieldf4;
  unsigned char paddingf5[3];

  virtual CRuntimeClass* GetRuntimeClass() const override;          // slot 0x00 0x542650
  virtual ~TMultiplayerMgr();                                       // slot 0x01 0x5427e0
  virtual void WriteTo(TStream* stream) override;                   // slot 0x05 0x542ff0
  virtual void ReadFrom(TStream* stream) override;                  // slot 0x06 0x542be0
  virtual void Free() override;                                     // slot 0x07 0x542b10
  virtual char CanHandleCityDialogActionFalse(int action) override; // slot 0x13 0x544e30
  virtual undefined
  InitializeMultiplayerManagerForSessionContext(CString param_1); // slot 0x25 0x542900

  TMultiplayerMgr();
};
