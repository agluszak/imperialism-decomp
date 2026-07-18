#pragma once

#include "game/TCommand.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c130
class TNewGameCommand : public TCommand {
public:
  DECLARE_DYNCREATE(TNewGameCommand)
  virtual ~TNewGameCommand() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4878e0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94 inherited unchanged (0x487900)
  virtual void DoIt() override; // slot 0x0b 0x49ddb0

  // Fully inlined at every construction site (base TCommand ctor call + vtable
  // store); defined in-class so `new TNewGameCommand()` reproduces that shape.
  TNewGameCommand() : TCommand() {}
};
