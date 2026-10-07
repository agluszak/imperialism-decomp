#pragma once

#include "compat.h"

#include "game/ui_screens/TMegaPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006580b0
class TNumberedIcon : public TMegaPicture {
public:
  DECLARE_DYNCREATE(TNumberedIcon)
  virtual ~TNumberedIcon() override;                // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override;      // slot 0x37 0x5074e0
  virtual void SetValue(short value, bool refresh); // slot 0x76 0x5076d0
  virtual void InstallNumberText();                 // slot 0x77 0x507570
  class TNumberText* numberText;                    // +0xac

  TNumberedIcon();

  void INumberedIcon(TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam4,
                     int layoutParam5, short pictureId, short value);
};
ASSERT_SIZE(TNumberedIcon, 0xb0);
