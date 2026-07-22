#pragma once

#include "game/TDropShadowText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642b18
class TRadioText : public TDropShadowText {
public:
  DECLARE_DYNCREATE(TRadioText)
  virtual ~TRadioText() override;               // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x579490
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5794b0
  // Refreshes self, then notifies the owner panel via its slot 0x13c
  // (TView::ForceRedraw, same "selection confirmed" hook TTextList uses).
  virtual void RefreshAndNotifyOwnerSlot13C(); // slot 0x76 0x579580

  TRadioText();

  // 0x98 — not initialized by the ctor (0x43d990 writes only the vtable); a 0/1
  // "this option is selected" flag toggled by the owning
  // TRadioTextCluster::SetSelectedTextOptionByTag (0x5797c0) as it walks childList44.
  unsigned char isSelectedOption98;
  unsigned char pad99[3]; // 0x99 — not read/written by SetSelectedTextOptionByTag
};
ASSERT_SIZE(TRadioText, 0x9c);
