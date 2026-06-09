#include "game/TPlacard.h"

int g_pClassDescTPlacard;

// FUNCTION: IMPERIALISM 0x0058b960
void* __cdecl CreateTPlacardInstance(void) {
  return new TPlacard();
}

// FUNCTION: IMPERIALISM 0x0058b9f0
void* __cdecl GetTPlacardClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTPlacard);
}

// FUNCTION: IMPERIALISM 0x0058ba10
TPlacard::TPlacard() : TPictureButton() {
  this->glyph90 = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058ba40
// TPlacard::`scalar deleting destructor'

TPlacard::~TPlacard() {}

#include "game/CString.h"

#include "game/trade_quickdraw.h"

undefined4 FormatStringWithVarArgsToSharedRef(void);
undefined4 thunk_MeasureTextExtentWithCachedQuickDrawStyle(void);
undefined4 thunk_DrawTextWithCachedQuickDrawStyleState(void);

const unsigned int kAddrDecimalFormat = 0x0069430C;

// FUNCTION: IMPERIALISM 0x0058bfe0
void TPlacard::RenderRightAlignedNumericOverlayWithShadow() {
  CString sharedStringRef;
  int* sharedStringRefPtr = reinterpret_cast<int*>(&sharedStringRef);

  reinterpret_cast<void(__fastcall*)(void*)>(thunk_RenderHintHelperWithCtrlModifierOverlay)(this);

  if (this->glyph90 != 0) {
    reinterpret_cast<void(__cdecl*)()>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)();
    reinterpret_cast<void(__cdecl*)(int*, const char*, int)>(FormatStringWithVarArgsToSharedRef)(
        sharedStringRefPtr, reinterpret_cast<const char*>(kAddrDecimalFormat),
        static_cast<int>(this->glyph90));

    short textWidth =
        reinterpret_cast<short(__cdecl*)()>(thunk_MeasureTextExtentWithCachedQuickDrawStyle)();
    short textX =
        (short)(*reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x34) - textWidth);
    short textY = (short)(*reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x38) - 2);
    SetQuickDrawTextOrigin(textX, textY);
    reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        sharedStringRefPtr);

    reinterpret_cast<void(__cdecl*)()>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)();
    SetQuickDrawTextOrigin((short)(textX - 1), (short)(textY - 1));
    reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        sharedStringRefPtr);
  }

  sharedStringRef.~CString();
}
