#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00658fa0
class TTownNameDialog : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TTownNameDialog)
  virtual ~TTownNameDialog() override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;

  TTownNameDialog();
};
ASSERT_SIZE(TTownNameDialog, 0x94);
