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
  virtual ~TNumberedItem() override;
  virtual void Draw(RECT* rectBuffer) override;
  short iconRowIndex; // icon-strip row (badge background variant)
  short badgeCount;   // the number drawn on the badge

  TNumberedItem();
  void INumberedItem(TView* panel, int* position, int* size, short resourceIconIndex, short count);
};
ASSERT_SIZE(TNumberedItem, 0xb0);
