#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

struct WNetSelectionRecord;

// VTABLE: IMPERIALISM 0x006435e8
class TJoinSelectorDialog : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TJoinSelectorDialog)
  virtual ~TJoinSelectorDialog() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  // NOOP: verified empty in original 0x0054e6c6
  TJoinSelectorDialog() {}

  void AddJoinableGameOptionEntry(const char* label, WNetSelectionRecord* record);
  WNetSelectionRecord* GetSelectedJoinableGame();
};
ASSERT_SIZE(TJoinSelectorDialog, 0x94);
