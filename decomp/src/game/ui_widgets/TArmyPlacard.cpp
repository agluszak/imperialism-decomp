#include "game/ui_widgets/TArmyPlacard.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/military/TArmyMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/core/CString.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_text_label_helpers_decls.h"

IMPLEMENT_DYNCREATE(TArmyPlacard, TPicture)

// FUNCTION: IMPERIALISM 0x0058bed0
TArmyPlacard::TArmyPlacard() {
  this->glyph = -1;
}

// FUNCTION: IMPERIALISM 0x0058bf30
TArmyPlacard::~TArmyPlacard() {}

// FUNCTION: IMPERIALISM 0x0058bf50
void TArmyPlacard::SetValue(short value, bool refreshNow) {
  short activeNationId = g_pSimMgr->GetPlayerCountry();
  short capValue =
      g_pTechMgr->nationCapRows1e8[activeNationId].slots[controlTag - kControlTagArmyPlacardFirst];
  short pictureId = capValue + 0x4c4;
  if (value != glyph) {
    if (value <= 0) {
      pictureId += 0x1e;
    }
    SetPictureRsrcID(pictureId, true);
    if (refreshNow) {
      RefreshControl();
    }
  }
  glyph = value;
}

// FUNCTION: IMPERIALISM 0x0058bfe0
void TArmyPlacard::Draw(RECT* rectBuffer) {
  CString countText;

  TPicture::Draw(rectBuffer);

  if (glyph != 0) {
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b67);
    countText.Format(g_szDecimalFormat, static_cast<int>(glyph));

    short textWidth = MeasureTextExtentWithCachedQuickDrawStyle(&countText);
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(frameWidth - textWidth),
                                            static_cast<short>(frameHeight - 2));
    DrawTextWithCachedQuickDrawStyleState(&countText);

    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b6c);
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(frameWidth - textWidth - 1),
                                            static_cast<short>(frameHeight - 3));
    DrawTextWithCachedQuickDrawStyleState(&countText);
  }
}

// FUNCTION: IMPERIALISM 0x0058c140
void TArmyPlacard::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (sourceHandler->controlTag == kControlTagPlus) { // "plus"
    short categoryId = controlTag - 0x6330;
    short tileIndex = g_pMapContextActionManager->pendingMapActionIndex;
    short unitCount = g_pMapContextActionManager->DeSelectUnitType(categoryId, tileIndex);
    SetValue(unitCount, true);
    return;
  }
  if (sourceHandler->controlTag == kControlTagMinu) { // "minu"
    short categoryId = controlTag - 0x6330;
    short tileIndex = g_pMapContextActionManager->pendingMapActionIndex;
    short unitCount = g_pMapContextActionManager->SelectUnitType(categoryId, tileIndex);
    SetValue(unitCount, true);
  }
}
