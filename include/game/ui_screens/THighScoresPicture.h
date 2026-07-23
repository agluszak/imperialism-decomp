#pragma once

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00643ea8
class THighScoresPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(THighScoresPicture)
  virtual ~THighScoresPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00575770
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x575320
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x575460
  virtual void Hilite() override;               // slot 0x73 0x45ada0

  // NOOP: verified empty in original 0x00455a91 (trivial inline ctor: the builder
  // expansion site emits only the base ctor call + vtbl install)
  THighScoresPicture() {}

  // Loaded from Data\scores.dat by DoPostCreate: 10 leading 4-byte score values,
  // then 10 32-byte score-entry records (name + associated fields; layout beyond raw
  // bytes not yet recovered).
  int scoreValues94[10];                  // +0x94
  unsigned char scoreRecordsBc[10][0x20]; // +0xbc
};
