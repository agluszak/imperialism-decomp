#pragma once

#include "compat.h"

#include "game/ui_screens/TBook.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063f428
class TBattleDetailBook : public TBook {
public:
  DECLARE_DYNCREATE(TBattleDetailBook)
  virtual ~TBattleDetailBook() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;

  // NOOP: verified empty in original 0x004aea08
  TBattleDetailBook() {}
};
ASSERT_SIZE(TBattleDetailBook, 0x98);
