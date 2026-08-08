#pragma once

#include "compat.h"

#include "game/ui_screens/TBook.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063f428
class TBattleDetailBook : public TBook {
public:
  DECLARE_DYNCREATE(TBattleDetailBook)
  virtual ~TBattleDetailBook() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004aea90

  // NOOP: verified empty in original 0x004aea08 (no standalone TBattleDetailBook::TBattleDetailBook body exists: CreateObject 0x004ae9d0 inlines this default ctor, calling the TPicture base ctor directly at that site)
  TBattleDetailBook() {}
};
ASSERT_SIZE(TBattleDetailBook, 0x98);
