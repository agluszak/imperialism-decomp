#include "game/navy_ui/TShipPlacard.h"

#include "game/ui_screens/CString.h"
#include "game/ui_core/TPicture.h"
#include "game/navy_ui/TShipFractionCluster.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
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
// FUNCTION: IMPERIALISM 0x005692d0
TShipPlacard::~TShipPlacard() {}

// FUNCTION: IMPERIALISM 0x005692f0
void TShipPlacard::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
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
