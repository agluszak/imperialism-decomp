#include "game/TMerchantBoyView.h"

#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

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
void TMerchantBoyView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other ApplyRectSlot110s

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6a);
  // `label` is reused for both the commodity name AND (after being drawn) the
  // status text below -- ground truth reuses the same stack slot for both, not
  // two separate locals. `unusedLabel` is constructed and destroyed alongside it
  // but never read anywhere in the disassembly (same as TNavyBoyView's).
  CString label;
  CString unusedLabel;
  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xc, 0x2b6a, 3);

  // field60 is re-read fresh at each site here (not cached in a local) -- matches the
  // original, which re-fetches `this->field60` for every access.
  short commodityCode = *reinterpret_cast<short*>(static_cast<char*>(field60));
  FormatLocalizedCommodityCountLabelByIndex(&label, commodityCode, -1);

  SetQuickDrawTextOriginWithContextOffset(0x50, 0x18);
  DrawTextWithCachedQuickDrawStyleState(&label);

  short statusFlag = *reinterpret_cast<short*>(static_cast<char*>(field60) + 2);
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
