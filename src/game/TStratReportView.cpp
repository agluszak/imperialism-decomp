// TStratReportView wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"
#include "game/TStratReportView.h"
#include "game/global_data_tables.h"

#include <new>

IMPLEMENT_DYNCREATE(TStratReportView, TView)

// FUNCTION: IMPERIALISM 0x0058e330
TStratReportView* __cdecl CreateTStratReportViewInstance(void) {
  return new TStratReportView();
}

// FUNCTION: IMPERIALISM 0x0058e3c0
TStratReportView::TStratReportView() : TView() {}

// SYNTHETIC: IMPERIALISM 0x0058e3f0
// TStratReportView::`scalar deleting destructor'
TStratReportView::~TStratReportView() {}

// FUNCTION: IMPERIALISM 0x0058e460
void TStratReportView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  // TODO: not yet ported -- draws the battle-outcome header winner/loser
  // score lines via CString formatting + THQButton text rendering.
}
