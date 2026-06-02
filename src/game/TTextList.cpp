#include "game/TTextList.h"
#include "game/generated/vcall_facades.h"
#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTTextList = 0;
char g_vtblTTextList = 0;
}

undefined4 thunk_MapUiThemeCodeToStyleFlags(void);
undefined4 ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(void);
undefined4 thunk_FillRectWithQuickDrawBrushAndContextOffset(void);
undefined4 thunk_MeasureTextExtentWithCachedQuickDrawStyle(void);
undefined4 SetQuickDrawColorAndSyncGlobals(void);
undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);
undefined4 thunk_DrawTextWithCachedQuickDrawStyleState(void);

// FUNCTION: IMPERIALISM 0x0057ab70
TTextList* TTextList::CreateTTextListInstance() {
  return new TTextList();
}

// FUNCTION: IMPERIALISM 0x0057ac30
void* TTextList::GetTTextListClassNamePointer() {
  return &g_pClassDescTTextList;
}

// FUNCTION: IMPERIALISM 0x0057acc0
void TTextList::RenderTextListRowsWithSelectionHighlight() {
  int styleFlags1 = 0;
  int styleFlags2 = 0;
  reinterpret_cast<void(__cdecl*)(int, int*)>(thunk_MapUiThemeCodeToStyleFlags)(0x2B6C, &styleFlags1);
  reinterpret_cast<void(__cdecl*)(int, int*)>(thunk_MapUiThemeCodeToStyleFlags)(0x2B6A, &styleFlags2);
  
  reinterpret_cast<void(__cdecl*)(int, int, int)>(
      ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)(0, 0x0e, 0x2b6c);

  short currentY = 0;
  if (itemHeight + currentY < field38) {
    int startIdx = scrollOffset;
    TTextListItem* pItem = &items[startIdx];
    int idx = startIdx;
    
    while (idx < totalItems) {
      StringShared tempString;
      tempString.ConstructFromCStrOrResourceId(pItem->text);
      
      if (idx == selectedIndex) {
        VCall_UiRuntime_ApplyLegendSplitSlot34(g_pUiRuntimeContext, 5);
        
        RECT rect;
        rect.left = 0;
        rect.top = currentY;
        rect.right = field34;
        rect.bottom = currentY + itemHeight;
        
        reinterpret_cast<void(__cdecl*)(RECT*)>(
            thunk_FillRectWithQuickDrawBrushAndContextOffset)(&rect);
      }
      
      int textWidth = 0;
      reinterpret_cast<int(__cdecl*)(StringShared*, int*)>(
          thunk_MeasureTextExtentWithCachedQuickDrawStyle)(&tempString, &textWidth);
      
      short textX = static_cast<short>(field34 / 2) - static_cast<short>(textWidth / 2);
      
      reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawColorAndSyncGlobals)(styleFlags2);
      reinterpret_cast<void(__cdecl*)(short, short)>(
          thunk_SetQuickDrawTextOriginWithContextOffset)(textX + 1, currentY + 12);
      reinterpret_cast<void(__fastcall*)(void*, int)>(
          thunk_DrawTextWithCachedQuickDrawStyleState)(&tempString, 0);
          
      reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawColorAndSyncGlobals)(styleFlags1);
      reinterpret_cast<void(__cdecl*)(short, short)>(
          thunk_SetQuickDrawTextOriginWithContextOffset)(textX, currentY + 11);
      reinterpret_cast<void(__fastcall*)(void*, int)>(
          thunk_DrawTextWithCachedQuickDrawStyleState)(&tempString, 0);
          
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
void TTextList::HandleTextListScrollSelectionChange(int* pScrollData) {
  int index = (pScrollData[1] / itemHeight) + scrollOffset;
  if (index < totalItems) {
    selectedIndex = index;
    
    VCall_TextList_OnSelectionChange(this);
    
    RECT rect;
    VCall_TextList_GetRect(this, &rect);
    
    RECT localRect;
    CopyRect(&localRect, &rect);
    
    reinterpret_cast<TControl*>(this->field20)->InvalidateCityDialogRectRegion(&localRect, 1);
        
    VCall_TextList_OnSelectionConfirmed(this);
    
    VCall_Parent_DispatchEvent(reinterpret_cast<void*>(this->field20), 4, this, 0);
  }
}
