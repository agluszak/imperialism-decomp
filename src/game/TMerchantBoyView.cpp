#include "game/TMerchantBoyView.h"

#include "game/battle_report_records.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x004af710
// TMerchantBoyView::`scalar deleting destructor'
TMerchantBoyView::~TMerchantBoyView() {}
// SYNTHETIC: IMPERIALISM 0x004af6a0
// TMerchantBoyView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004af760
// TMerchantBoyView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMerchantBoyView, TView)

TMerchantBoyView::TMerchantBoyView() {}

// FUNCTION: IMPERIALISM 0x004af780
void TMerchantBoyView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6a);
  // `label` is reused for both the commodity name AND (after being drawn) the
  // status text below -- ground truth reuses the same stack slot for both, not
  // two separate locals. `unusedLabel` is constructed and destroyed alongside it
  // but never read anywhere in the disassembly (same as TNavyBoyView's).
  CString label;
  CString unusedLabel;
  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xc, 0x2b6a, 3);

  short commodityCode = battleDetail60->payload.merchant.commodityType00;
  FormatLocalizedCommodityCountLabelByIndex(&label, commodityCode, -1);

  SetQuickDrawTextOriginWithContextOffset(0x50, 0x18);
  DrawTextWithCachedQuickDrawStyleState(&label);

  short statusFlag = battleDetail60->payload.merchant.completed02;
  int themeCode;
  if (statusFlag != 0) {
    g_pSimMgr->GetString(0x273c, 0x1c, &label);
    themeCode = 0x2b69;
  } else {
    g_pSimMgr->GetString(0x273c, 0x1b, &label);
    themeCode = 0x2b67;
  }
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(1, 0xc, themeCode);
  MeasureTextExtentWithCachedQuickDrawStyle(&label); // result unused; primes the cached font
  SetQuickDrawTextOriginWithContextOffset(0x50, 0x26);
  DrawTextWithCachedQuickDrawStyleState(&label);

  SetQuickDrawStrokeColor(0x13);
}
