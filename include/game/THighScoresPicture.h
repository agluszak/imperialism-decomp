#pragma once

#include "game/TNoHilitePicture.h"
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

  // Loaded from Data\scores.dat by DoPostCreate: ten score values interleaved with ten
  // 32-byte name records. Draw (0x575460) walks them in lockstep, formatting the value
  // with "%d" and constructing a CString straight from the record pointer -- so each
  // record is just a NUL-terminated player name, not a struct.
  int scoreValues94[10];       // +0x94
  char scoreNamesBc[10][0x20]; // +0xbc
};
