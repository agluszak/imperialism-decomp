#pragma once

#include "game/TBook.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063f428
class TBattleDetailBook : public TBook {
public:
  DECLARE_DYNCREATE(TBattleDetailBook)
  virtual ~TBattleDetailBook() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004aea90

  TBattleDetailBook();
};
