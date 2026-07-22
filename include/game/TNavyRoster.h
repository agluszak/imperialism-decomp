#pragma once

#include "game/TMilitaryPageView.h"

class TTaskForce;
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065cbd0
class TNavyRoster : public TMilitaryPageView {
public:
  DECLARE_DYNCREATE(TNavyRoster)
  virtual ~TNavyRoster() override;                 // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;                   // slot 0x28 0x564fe0
  virtual void StuffValues(TTaskForce* taskForce); // slot 0x6e 0x564dc0

  TNavyRoster();

  // StuffValues stores its task-force argument, resolves 'cls0'..'cls3' as a real
  // contiguous TView* array, and then builds one line per linked task-force entry.
  TTaskForce* taskForce88;
  int unresolvedZero8C; // constructor-only zero dword
  TView* classControls90[4];
  unsigned char paddingA0[0xd0 - 0xa0];
};
