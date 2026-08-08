#include "game/military_ui/TInterruptusView.h"

#include "game/battle_report_records.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"

// SYNTHETIC: IMPERIALISM 0x004afd30
// TInterruptusView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004afd60
TInterruptusView::~TInterruptusView() {}
// SYNTHETIC: IMPERIALISM 0x004afcc0
// TInterruptusView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004afd80
// TInterruptusView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInterruptusView, TItemBoyView)

// FUNCTION: IMPERIALISM 0x004afda0
void TInterruptusView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  CString label;
  CString kindText;
  CString countText;
  CString nationLabel;

  short kindIdx = battleDetail60->resourceType;
  g_pSimMgr->GetStringPrelude(kindIdx, &kindText);

  short count = battleDetail60->stockOrRequired;
  countText.Format(g_szDecimalFormat, count);

  CString templateText;
  // Same group-0x273c template lookup as TItemBoyView but index 0x1e (one extra
  // substitution slot for the interrupting nation's name below), matching the
  // extra scanBracketExpressions token this override passes.
  g_pSimMgr->GetString(0x273c, 0x1e, &templateText);

  short minorIndex = battleDetail60->strengthBucket;
  g_apTerrainTypeDescriptorTable[minorIndex]->FormatOverlayTerrainLabelText(&nationLabel);

  scanBracketExpressions(g_pSimMgr, &label, static_cast<const char*>(templateText),
                         static_cast<const char*>(countText), static_cast<const char*>(kindText),
                         static_cast<const char*>(nationLabel));

  // Inherited from TItemBoyView: same header-draw + icon-row blit body.
  DrawItemHeaderAndIconRows(&label);
}
