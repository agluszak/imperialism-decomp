// UI wrapper class quads extracted from trade_screen.

#include "game/ui_widget_shared.h"

struct tagRECT {
  int left;
  int top;
  int right;
  int bottom;
};

extern "C" int __stdcall CopyRect(tagRECT* lprcDst, const tagRECT* lprcSrc);
undefined4 thunk_InvalidateCityDialogRectRegion(void);

struct PlacardViewLayout {
  void* vftable;
  char pad_04[0x30];
  int widthAt34;
  int baselineAt38;
  char pad_3c[0x54];
  short valueAt90;
};

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x0058b960
PlacardState* __cdecl CreateTPlacardInstance(void) {
  PlacardState* placard = reinterpret_cast<PlacardState*>(AllocateWithFallbackHandler(0x94));
  if (placard != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
    placard->vftable = reinterpret_cast<void*>(&g_vtblTPlacard);
    placard->placardValue = 0;
  }
  return placard;
}

// FUNCTION: IMPERIALISM 0x0058b9f0
void* __cdecl GetTPlacardClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTPlacard);
}

// FUNCTION: IMPERIALISM 0x0058ba10
PlacardState* __fastcall ConstructTPlacardBaseState(PlacardState* placard) {
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
  placard->vftable = reinterpret_cast<void*>(&g_vtblTPlacard);
  placard->placardValue = 0;
  return placard;
}

// FUNCTION: IMPERIALISM 0x0058ba40
PlacardState* __fastcall DestructTPlacardAndMaybeFree(PlacardState* placard, int unusedEdx,
                                                      unsigned char freeSelfFlag) {
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(placard);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)placard);
  }
  return placard;
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif

// FUNCTION: IMPERIALISM 0x0058bab0
void PlacardState::WrapperFor_thunk_NoOpUiLifecycleHook_At0058bab0() {
  thunk_NoOpUiLifecycleHook();
  int enabled = (placardValue == 0) ? 0 : 1;
  reinterpret_cast<void(__fastcall*)(PlacardState*, int, int)>(
      (*reinterpret_cast<void***>(this))[0xa4 / 4])(this, enabled, 1);
}

// FUNCTION: IMPERIALISM 0x0058bb50
void PlacardState::WrapperFor_thunk_InvalidateCityDialogRectRegion_At0058bb50(int arg1, int arg2) {
  short requestedValue = (short)arg1;
  if (requestedValue != placardValue) {
    if (requestedValue == 0) {
      reinterpret_cast<void(__fastcall*)(PlacardState*, int, int)>(
          (*reinterpret_cast<void***>(this))[0xa4 / 4])(this, 0, (int)(char)arg2);
    } else if (placardValue == 0) {
      reinterpret_cast<void(__fastcall*)(PlacardState*, int, int)>(
          (*reinterpret_cast<void***>(this))[0xa4 / 4])(this, 1, (int)(char)arg2);
    }
    placardValue = requestedValue;
    if ((char)arg2 != 0) {
      PlacardViewLayout* layout = reinterpret_cast<PlacardViewLayout*>(this);
      tagRECT sourceRect;
      tagRECT invalidateRect;
      sourceRect.top = layout->baselineAt38 - 0xc;
      sourceRect.left = (short)(layout->widthAt34 / 2) - 10;
      sourceRect.right = sourceRect.left + 0x14;
      sourceRect.bottom = layout->baselineAt38 - 1;
      CopyRect(&invalidateRect, &sourceRect);
      reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
          (int)&invalidateRect, 1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0058bc60
void PlacardState::RenderPlacardValueTextWithShadow() {
  if (placardValue != 0) {
    thunk_NoOpUiLifecycleHook();
  }
}
