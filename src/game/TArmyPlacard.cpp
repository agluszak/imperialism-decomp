#include "game/TArmyPlacard.h"

CRuntimeClass g_pClassDescTArmyPlacard = {nullptr, 0, 0, nullptr, nullptr};

// FUNCTION: IMPERIALISM 0x0058be30
void* __cdecl CreateTArmyPlacardInstance(void) {
  return new TArmyPlacard();
}

// FUNCTION: IMPERIALISM 0x0058beb0
CRuntimeClass* TArmyPlacard::GetRuntimeClass() {
  return &g_pClassDescTArmyPlacard;
}

// FUNCTION: IMPERIALISM 0x0058bed0
TArmyPlacard::TArmyPlacard() : TPictureButton() {
  this->glyph90 = -1;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058bf00
// TArmyPlacard::`scalar deleting destructor'

TArmyPlacard::~TArmyPlacard() {}

#include "game/CString.h"
#include "game/trade_quickdraw.h"
#include "game/CRuntimeClass.h"

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
