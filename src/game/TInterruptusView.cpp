#include "game/TInterruptusView.h"

#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"

// SYNTHETIC: IMPERIALISM 0x004afd30
// TInterruptusView::`scalar deleting destructor'
TInterruptusView::~TInterruptusView() {}
// SYNTHETIC: IMPERIALISM 0x004afcc0
// TInterruptusView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004afd80
// TInterruptusView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInterruptusView, TItemBoyView)

TInterruptusView::TInterruptusView() {}

// FUNCTION: IMPERIALISM 0x004afda0
void TInterruptusView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  CString label;
  CString kindText;
  CString countText;
  CString nationLabel;

  // field60 is re-read fresh at each site here (not cached in a local) -- matches the
  // original, which re-fetches `this->field60` for every access instead of keeping it
  // live in a register across these calls.
  short kindIdx = *reinterpret_cast<short*>(static_cast<char*>(field60));
  g_pSimMgr->GetStringPrelude(kindIdx, &kindText);

  short count = *reinterpret_cast<short*>(static_cast<char*>(field60) + 2);
  countText.Format(g_szDecimalFormat, count);

  CString templateText;
  // Same group-0x273c template lookup as TItemBoyView but index 0x1e (one extra
  // substitution slot for the interrupting nation's name below), matching the
  // extra scanBracketExpressions token this override passes.
  g_pSimMgr->GetString(0x273c, 0x1e, &templateText);

  short minorIndex = *reinterpret_cast<short*>(static_cast<char*>(field60) + 0x24);
  g_apNationAuxRuntimeStateSlots[minorIndex]->FormatOverlayTerrainLabelText(&nationLabel);

  scanBracketExpressions(g_pSimMgr, &label, static_cast<const char*>(templateText),
                         static_cast<const char*>(countText), static_cast<const char*>(kindText),
                         static_cast<const char*>(nationLabel));

  // Inherited from TItemBoyView: same header-draw + icon-row blit body.
  DrawItemHeaderAndIconRows(&label);
}
