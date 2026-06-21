#include "game/TArmyPlacard.h"
#include "game/mfc.h"
#include "game/CString.h"
#include "game/trade_quickdraw.h"
#include "game/UiRuntimeContext.h"
#include "game/TTechMgr.h"
#include "game/TEvent.h"

CRuntimeClass g_pClassDescTArmyPlacard = {nullptr, 0, 0, nullptr, nullptr};

// FUNCTION: IMPERIALISM 0x0058be30
void* __cdecl CreateTArmyPlacardInstance(void) {
  return new TArmyPlacard();
}

// FUNCTION: IMPERIALISM 0x0058beb0
CRuntimeClass* TArmyPlacard::GetRuntimeClass() const {
  return &g_pClassDescTArmyPlacard;
}

// FUNCTION: IMPERIALISM 0x0058bed0
TArmyPlacard::TArmyPlacard() : TPictureResourceEntryBase() {
  this->glyph90 = -1;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058bf00
// TArmyPlacard::`scalar deleting destructor'

TArmyPlacard::~TArmyPlacard() {}

// FUNCTION: IMPERIALISM 0x0058bf50
bool TArmyPlacard::IsSelected(short value, bool refreshNow) {
  short activeNationId = g_pUiRuntimeContext->GetActiveNationId();
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

undefined4 FormatStringWithVarArgsToSharedRef(void);
undefined4 thunk_MeasureTextExtentWithCachedQuickDrawStyle(void);
undefined4 thunk_DrawTextWithCachedQuickDrawStyleState(void);

const unsigned int kAddrDecimalFormat = 0x0069430C;

// FUNCTION: IMPERIALISM 0x0058bfe0
void TArmyPlacard::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  CString sharedStringRef;
  int* sharedStringRefPtr = reinterpret_cast<int*>(&sharedStringRef);

  TPictureResourceEntryBase::ApplyRectSlot110(nullptr);

  if (this->glyph90 != 0) {
    reinterpret_cast<void(__cdecl*)()>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)();
    reinterpret_cast<void(__cdecl*)(int*, const char*, int)>(FormatStringWithVarArgsToSharedRef)(
        sharedStringRefPtr, reinterpret_cast<const char*>(kAddrDecimalFormat),
        static_cast<int>(this->glyph90));

    short textWidth = static_cast<short>(
        reinterpret_cast<int(__cdecl*)()>(thunk_MeasureTextExtentWithCachedQuickDrawStyle)());
    short textX = static_cast<short>(
        *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x34) - textWidth);
    short textY =
        static_cast<short>(*reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x38) - 2);

    SetQuickDrawTextOrigin(textX, textY);
    reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        sharedStringRefPtr);

    reinterpret_cast<void(__cdecl*)()>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)();
    SetQuickDrawTextOrigin(static_cast<short>(textX - 1), static_cast<short>(textY - 1));
    reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        sharedStringRefPtr);
  }

  sharedStringRef.~CString();
}

undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);

const unsigned int kAddrMapContextActionManager = 0x006a3338;

// FUNCTION: IMPERIALISM 0x0058c140
void TArmyPlacard::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)commandId;
  (void)sourceHandler;
  int* mapContextActionManager = *reinterpret_cast<int**>(kAddrMapContextActionManager);
  if (event != nullptr) {
    if (event->commandTag1c == 0x706c7573) { // "plus"
      short categoryId = this->controlTag - 0x6330;
      short tileIndex =
          *reinterpret_cast<short*>(reinterpret_cast<char*>(mapContextActionManager) + 0x31c);
      int unitId = reinterpret_cast<int(__cdecl*)(short, short)>(
          ActivateFirstActiveTacticalUnitByCategoryAtTile)(categoryId, tileIndex);
      this->IsSelected(unitId, true);
      return;
    }
    if (event->commandTag1c == 0x6d696e75) { // "minu"
      short categoryId = this->controlTag - 0x6330;
      short tileIndex =
          *reinterpret_cast<short*>(reinterpret_cast<char*>(mapContextActionManager) + 0x31c);
      int unitId = reinterpret_cast<int(__cdecl*)(short, short)>(
          ActivateFirstIdleTacticalUnitByCategoryAtTile)(categoryId, tileIndex);
      this->IsSelected(unitId, true);
    }
  }
}
