#pragma once

#include "game/ui_screens/TMegaPicture.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TObject;
class TTEView;

// VTABLE: IMPERIALISM 0x006582f0
class TNumberedItem : public TMegaPicture {
public:
  DECLARE_DYNCREATE(TNumberedItem)
  // slot 0x00 GetRuntimeClass owned by DECLARE_DYNCREATE (0x5077a0)
  virtual ~TNumberedItem() override;            // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5078a0
  // RTTI proves TNumberedItem is TMegaPicture (0xac) + these 4 bytes (0xb0 total) --
  // the base's own 0xac bytes must not be re-declared here as padding.
  short iconRowIndexAc; // +0xac icon-strip row (badge background variant)
  short badgeCountAe;   // +0xae the number drawn on the badge

  TNumberedItem();
  void InitializeNumberedResourceItem(TView* panel, int* position, int* size,
                                      short resourceIconIndex, short count);
};
