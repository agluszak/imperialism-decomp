#include "game/TShipPlacard.h"

#include "game/CString.h"
#include "game/TPicture.h"
#include "game/TShipFractionCluster.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x005691d0
// TShipPlacard::CreateObject

// SYNTHETIC: IMPERIALISM 0x00569250
// TShipPlacard::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipPlacard, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00569270
TShipPlacard::TShipPlacard() {}

// SYNTHETIC: IMPERIALISM 0x005692a0
// TShipPlacard::`scalar deleting destructor'
TShipPlacard::~TShipPlacard() {}

// FUNCTION: IMPERIALISM 0x005692f0
void TShipPlacard::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);
  short quantity = static_cast<TShipFractionCluster*>(ownerContext)->availableShipCount88;
  if (quantity > 0) {
    CString countText;
    countText.Format(g_szDecimalFormat, static_cast<int>(quantity));
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b67);
    short textWidth = MeasureTextExtentWithCachedQuickDrawStyle(&countText);
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(0x51 - textWidth / 2), 0x2f);
    DrawTextWithCachedQuickDrawStyleState(&countText);
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b6c);
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(0x50 - textWidth / 2), 0x2e);
    DrawTextWithCachedQuickDrawStyleState(&countText);
  }
}
