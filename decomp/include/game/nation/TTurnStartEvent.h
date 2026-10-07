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
  virtual ~TTurnStartEvent() override {}
  virtual void Execute();

  // Concrete event initializers replace the uninitialized 'erra' tag.
  int eventTag;

  TTurnStartEvent() : eventTag(kControlTagErra) {}
};

ASSERT_SIZE(TTurnStartEvent, 0x8);
