#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

struct WNetSelectionRecord;

// VTABLE: IMPERIALISM 0x006435e8
class TJoinSelectorDialog : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TJoinSelectorDialog)
  virtual ~TJoinSelectorDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0054e9a0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x54e730

  // NOOP: verified empty in original 0x0054e6c6 (no standalone TJoinSelectorDialog::TJoinSelectorDialog body exists: CreateObject 0x0054e690 inlines this default ctor, calling the TNoHilitePicture base ctor directly at that site)
  TJoinSelectorDialog() {}

  void AddJoinableGameOptionEntry(const char* label, WNetSelectionRecord* record);
  WNetSelectionRecord* GetSelectedJoinableGame();
};
ASSERT_SIZE(TJoinSelectorDialog, 0x94);
