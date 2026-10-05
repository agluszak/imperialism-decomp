#pragma once

#include "compat.h"

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

  THighScoresPicture() {}

  int scoreValues[10];       // +0x94
  char scoreNames[10][0x20]; // +0xbc
};
ASSERT_SIZE(THighScoresPicture, 0x1fc);
