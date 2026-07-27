#pragma once

#include "compat.h"

#include "game/ui_screens/TMegaPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006580b0
class TNumberedIcon : public TMegaPicture {
public:
  DECLARE_DYNCREATE(TNumberedIcon)
  virtual ~TNumberedIcon() override;           // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x5074e0
  virtual void SetValue(short value, unsigned char refresh); // slot 0x76 0x5076d0
  virtual void InstallNumberText();                          // slot 0x77 0x507570
  // TMegaPicture ends exactly at 0xac (ASSERT_SIZE); zeroed by the ctor. DoPostCreate
  // dereferences it through a vtable (ApplyBounds, slot 0x5a) when non-null.
  class TNumberText* numberTextAc; // +0xac

  TNumberedIcon();

  // Two-phase init: builds the TMegaPicture base with flags 5, installs the number
  // text, seeds its value, and parks the text in a 16x16 box anchored to the icon's
  // bottom-right corner. 0x00507420, __thiscall.
  void INumberedIcon(TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam4,
                     int layoutParam5, short pictureId, short value);
};
ASSERT_SIZE(TNumberedIcon, 0xb0);
