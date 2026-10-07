#pragma once

#include "compat.h"

#include "game/ui_screens/TMegaPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006580b0
class TNumberedIcon : public TMegaPicture {
public:
  DECLARE_DYNCREATE(TNumberedIcon)
  virtual ~TNumberedIcon() override;
  virtual void DoPostCreate(int arg) override;
  virtual void SetValue(short value, bool refresh);
  virtual void InstallNumberText();
  class TNumberText* numberText;

  TNumberedIcon();

  void INumberedIcon(TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam4,
                     int layoutParam5, short pictureId, short value);
};
ASSERT_SIZE(TNumberedIcon, 0xb0);
