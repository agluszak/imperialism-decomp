#include "game/TSelectedCivilianOrderState.h"

#include "decomp_types.h"
#include "game/TCivUnit.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x004d2c60
void TSelectedCivilianOrderState::SetActiveCivilianSelection(TCivUnit* entryContext,
                                                             int refreshCommandPanel) {
  typedef void (__fastcall *Func)(TSelectedCivilianOrderState*, int, TCivUnit*, int);
  reinterpret_cast<Func>(0x004d2c60)(this, 0, entryContext, refreshCommandPanel);
}

// FUNCTION: IMPERIALISM 0x004d2cf0
void TSelectedCivilianOrderState::QueueImmediateCivilianCommandAndCycleSelection(int commandType) {
  typedef void (__fastcall *Func)(TSelectedCivilianOrderState*, int, int);
  reinterpret_cast<Func>(0x004d2cf0)(this, 0, commandType);
}

// FUNCTION: IMPERIALISM 0x004d2d30
void TSelectedCivilianOrderState::ShowDisbandCivilianConfirmationDialog() {
  typedef void (__fastcall *Func)(TSelectedCivilianOrderState*, int);
  reinterpret_cast<Func>(0x004d2d30)(this, 0);
}
