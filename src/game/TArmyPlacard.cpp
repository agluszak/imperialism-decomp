#include "game/TArmyPlacard.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/CString.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/UiRuntimeContext.h"
#include "game/TSimMgr.h"
#include "game/TTechMgr.h"
#include "game/TSpaceCommand.h"
// FUNCTION: IMPERIALISM 0x0058be30
void* __cdecl CreateTArmyPlacardInstance(void) {
  return new TArmyPlacard();
}
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
bool TArmyPlacard::IsSelected(short value, bool refreshNow) {
  short activeNationId = g_pLocalizationTable->GetActiveNationId();
  short capValue =
      g_pCityOrderCapabilityState->nationCapRows1e8[activeNationId].caps[this->controlTag];
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
  return true;
}

// FUNCTION: IMPERIALISM 0x0058bfe0
void TArmyPlacard::ApplyRectSlot110(RECT* rectBuffer) {
  CString countText;

  TPicture::ApplyRectSlot110(rectBuffer);

  if (this->glyph90 != 0) {
    // Original (0x58bfe0): style (0, 10, 0x2b67) for the main pass and
    // (0, 10, 0x2b6c) for the offset shadow pass.
    ApplyUiTextStyleAndSyncColor(0, 10, 0x2b67);
    countText.Format(g_szDecimalFormat, static_cast<int>(this->glyph90));

    short textWidth = MeasureTextExtentWithCachedStyle(&countText);
    short textX = static_cast<short>(field34 - textWidth);
    short textY = static_cast<short>(field38 - 2);

    SetQuickDrawTextOrigin(textX, textY);
    DrawTextWithCachedStyle(&countText);

    ApplyUiTextStyleAndSyncColor(0, 10, 0x2b6c);
    SetQuickDrawTextOrigin(static_cast<short>(textX - 1), static_cast<short>(textY - 1));
    DrawTextWithCachedStyle(&countText);
  }
}

undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);

const unsigned int kAddrMapContextActionManager = 0x006a3338;

// FUNCTION: IMPERIALISM 0x0058c140
void TArmyPlacard::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)commandId;
  (void)sourceHandler;
  int* mapContextActionManager = *reinterpret_cast<int**>(kAddrMapContextActionManager);
  TSpaceCommand* spaceEvent = static_cast<TSpaceCommand*>(event);
  if (spaceEvent != nullptr) {
    if (spaceEvent->commandTag1c == 0x706c7573) { // "plus"
      short categoryId = this->controlTag - 0x6330;
      short tileIndex =
          *reinterpret_cast<short*>(reinterpret_cast<char*>(mapContextActionManager) + 0x31c);
      int unitId = reinterpret_cast<int(__cdecl*)(short, short)>(
          ActivateFirstActiveTacticalUnitByCategoryAtTile)(categoryId, tileIndex);
      this->IsSelected(unitId, true);
      return;
    }
    if (spaceEvent->commandTag1c == 0x6d696e75) { // "minu"
      short categoryId = this->controlTag - 0x6330;
      short tileIndex =
          *reinterpret_cast<short*>(reinterpret_cast<char*>(mapContextActionManager) + 0x31c);
      int unitId = reinterpret_cast<int(__cdecl*)(short, short)>(
          ActivateFirstIdleTacticalUnitByCategoryAtTile)(categoryId, tileIndex);
      this->IsSelected(unitId, true);
    }
  }
}

TArmyPlacard::~TArmyPlacard() {}
