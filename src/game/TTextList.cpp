#include "game/TTextList.h"
#include "game/global_data_tables.h"
#include "game/CString.h"
#include "game/TControl.h"
#include "game/TTextList_Virtuals.h"
#include "game/UiRuntimeContext.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/mfc.h"
#include "game/mfc.h"

extern "C" {
char g_vtblTTextList = 0;
}

undefined4 thunk_MapUiThemeCodeToStyleFlags(void);
undefined4 thunk_FillRectWithQuickDrawBrushAndContextOffset(void);
undefined4 thunk_MeasureTextExtentWithCachedQuickDrawStyle(void);
undefined4 thunk_DrawTextWithCachedQuickDrawStyleState(void);
undefined4 SetQuickDrawColorAndSyncGlobals(void);

// SYNTHETIC: IMPERIALISM 0x0045af30
// TTextList::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0057ab70
TTextList* TTextList::CreateTTextListInstance() {
  return new TTextList();
}
IMPLEMENT_DYNCREATE(TTextList, TView)

TTextList::TTextList() : TView() {
  itemHeight = 0x10;
  totalItems = 0;
  scrollOffset = 0;
  selectedIndex = -1;
}

// FUNCTION: IMPERIALISM 0x0057acc0
void TTextList::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;

  int styleFlags1 = 0;
  int styleFlags2 = 0;
  reinterpret_cast<void(__cdecl*)(int, int)>(thunk_MapUiThemeCodeToStyleFlags)(
      0x2B6C, reinterpret_cast<int>(&styleFlags1));
  reinterpret_cast<void(__cdecl*)(int, int)>(thunk_MapUiThemeCodeToStyleFlags)(
      0x2B6A, reinterpret_cast<int>(&styleFlags2));

  reinterpret_cast<void(__cdecl*)()>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)();

  short currentY = 0;
  if (itemHeight + currentY < field38) {
    int startIdx = scrollOffset;
    TTextListItem* pItem = &items[startIdx];
    int idx = startIdx;

    while (idx < totalItems) {
      CString tempString(pItem->text);

      if (idx == selectedIndex) {
        g_pUiRuntimeContext->ApplyLegendSplitSlot34(5);

        RECT rect;
        rect.left = 0;
        rect.top = currentY;
        rect.right = field34;
        rect.bottom = currentY + itemHeight;

        reinterpret_cast<void(__cdecl*)(RECT*)>(thunk_FillRectWithQuickDrawBrushAndContextOffset)(
            &rect);
      }

      short textWidth = static_cast<short>(
          reinterpret_cast<int(__cdecl*)()>(thunk_MeasureTextExtentWithCachedQuickDrawStyle)());
      short textX = static_cast<short>(field34 / 2) - static_cast<short>(textWidth / 2);
      int* tempStringRef = reinterpret_cast<int*>(&tempString);

      reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawColorAndSyncGlobals)(styleFlags2);
      reinterpret_cast<void(__cdecl*)(short, short)>(SetQuickDrawTextOriginWithContextOffset)(static_cast<short>(textX + 1), static_cast<short>(currentY + 12));
      reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
          tempStringRef);

      reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawColorAndSyncGlobals)(styleFlags1);
      reinterpret_cast<void(__cdecl*)(short, short)>(SetQuickDrawTextOriginWithContextOffset)(textX, static_cast<short>(currentY + 11));
      reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
          tempStringRef);

      currentY += itemHeight;
      idx++;
      pItem++;

      if (itemHeight + currentY >= field38) {
        break;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057af20
void TTextList::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3, int arg4) {
  (void)arg2;
  (void)arg3;
  (void)arg4;

  int* pScrollData = reinterpret_cast<int*>(point);
  int index = (pScrollData[1] / itemHeight) + scrollOffset;
  if (index < totalItems) {
    selectedIndex = index;

    reinterpret_cast<TTextList_Virtuals*>(this)->OnSelectionChangeSlotE4();

    RECT rect;
    reinterpret_cast<TTextList_Virtuals*>(this)->GetRectSlot12C(&rect);

    RECT localRect;
    CopyRect(&localRect, &rect);

    reinterpret_cast<TControl*>(this->ownerContext)->InvalidateCityDialogRectRegion(&localRect, 1);
    reinterpret_cast<TTextList_Virtuals*>(this)->OnSelectionConfirmedSlot13C();

    reinterpret_cast<TView*>(this->ownerContext)->DispatchEvent(4, this, 0);
  }
}
