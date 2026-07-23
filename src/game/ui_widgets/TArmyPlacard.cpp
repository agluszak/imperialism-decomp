#include "game/TArmyPlacard.h"
#include "game/TArmyMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/CString.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/TViewMgr.h"
#include "game/TSimMgr.h"
#include "game/TTechMgr.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x0058be30
// TArmyPlacard::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058beb0
// TArmyPlacard::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyPlacard, TPicture)

// FUNCTION: IMPERIALISM 0x0058bed0
TArmyPlacard::TArmyPlacard() : TPicture() {
  this->glyph90 = -1;
}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x0058bf00
// TArmyPlacard::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058bf50
void TArmyPlacard::SetValue(short value, unsigned char refreshNow) {
  short activeNationId = g_pSimMgr->GetActiveNationId();
  short capValue =
      g_pCityOrderCapabilityState->nationCapRows1e8[activeNationId].slots[9 + this->controlTag];
  short pictureId = capValue + 0x4c4;
  if (value != this->glyph90) {
    if (value < 1) {
      pictureId = capValue + 0x4e2;
    }
    this->SetPictureResourceIdAndRefresh(pictureId, true);
    if (refreshNow) {
      this->RefreshControl();
    }
  }
  this->glyph90 = value;
}

// FUNCTION: IMPERIALISM 0x0058bfe0
void TArmyPlacard::Draw(RECT* rectBuffer) {
  CString countText;

  TPicture::Draw(rectBuffer);

  if (this->glyph90 != 0) {
    // Original (0x58bfe0): style (0, 10, 0x2b67) for the main pass and
    // (0, 10, 0x2b6c) for the offset shadow pass.
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b67);
    countText.Format(g_szDecimalFormat, static_cast<int>(this->glyph90));

    short textWidth = MeasureTextExtentWithCachedQuickDrawStyle(&countText);
    short textX = static_cast<short>(frameWidth34 - textWidth);
    short textY = static_cast<short>(frameHeight38 - 2);

    SetQuickDrawTextOriginWithContextOffset(textX, textY);
    DrawTextWithCachedQuickDrawStyleState(&countText);

    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b6c);
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(textX - 1),
                                            static_cast<short>(textY - 1));
    DrawTextWithCachedQuickDrawStyleState(&countText);
  }
}

// FUNCTION: IMPERIALISM 0x0058c140
void TArmyPlacard::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)commandId;
  (void)event;
  if (sourceHandler->controlTag == 0x706c7573) { // "plus"
    short categoryId = this->controlTag - 0x6330;
    short tileIndex = g_pMapContextActionManager->pendingMapActionIndex;
    short unitCount = g_pMapContextActionManager->ActivateFirstActiveTacticalUnitByCategoryAtTile(
        categoryId, tileIndex);
    this->SetValue(unitCount, 1);
    return;
  }
  if (sourceHandler->controlTag == 0x6d696e75) { // "minu"
    short categoryId = this->controlTag - 0x6330;
    short tileIndex = g_pMapContextActionManager->pendingMapActionIndex;
    short unitCount = g_pMapContextActionManager->ActivateFirstIdleTacticalUnitByCategoryAtTile(
        categoryId, tileIndex);
    this->SetValue(unitCount, 1);
  }
}

TArmyPlacard::~TArmyPlacard() {}
