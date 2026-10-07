#pragma once

#include "compat.h"

#include "game/ui_screens/TMegaPicture.h"
#include "game/mfc.h"

class TObject;
class TTEView;

// VTABLE: IMPERIALISM 0x006582f0
class TNumberedItem : public TMegaPicture {
public:
  DECLARE_DYNCREATE(TNumberedItem)
  virtual ~TNumberedItem() override;            // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5078a0
  short iconRowIndex;                           // +0xac icon-strip row (badge background variant)
  short badgeCount;                             // +0xae the number drawn on the badge

  TNumberedItem();
  void INumberedItem(TView* panel, int* position, int* size, short resourceIconIndex, short count);
};
ASSERT_SIZE(TNumberedItem, 0xb0);
