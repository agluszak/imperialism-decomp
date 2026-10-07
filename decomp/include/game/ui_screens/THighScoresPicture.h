#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00643ea8
class THighScoresPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(THighScoresPicture)
  virtual ~THighScoresPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void Hilite() override;

  // NOOP: verified empty in original 0x00455a91
  THighScoresPicture() {}

  int scoreValues[10];
  char scoreNames[10][0x20];
};
ASSERT_SIZE(THighScoresPicture, 0x1fc);
