#pragma once

#include "game/app/TObject.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00653d90
class TTurnStartEvent : public TObject {
public:
  DECLARE_DYNCREATE(TTurnStartEvent)
  // FUNCTION: IMPERIALISM 0x004e6660
  virtual ~TTurnStartEvent() override {} // slot 0x01 (scalar deleting destructor)
  virtual void Execute();                // slot 0x0a 0x4e6610

  // Concrete event initializers replace the uninitialized 'erra' tag.
  int eventTag04; // +0x04

  TTurnStartEvent() : eventTag04(kControlTagErra) {}
};

ASSERT_SIZE(TTurnStartEvent, 0x8);
