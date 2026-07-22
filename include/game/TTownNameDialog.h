#pragma once

#include "game/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00658fa0
class TTownNameDialog : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TTownNameDialog)
  virtual ~TTownNameDialog() override;          // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x51bb90
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x51bcc0

  TTownNameDialog();
};
