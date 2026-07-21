#include "game/TTextList.h"
#include "game/global_data_tables.h"
#include "game/CString.h"
#include "game/TControl.h"
#include "game/UiRuntimeContext.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/mfc.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0045af30
// TTextList::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x0057ab70
// TTextList::CreateObject
// SYNTHETIC: IMPERIALISM 0x0057ac30
// TTextList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTextList, TView)

// FUNCTION: IMPERIALISM 0x0045aee0
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
  MapUiThemeCodeToStyleFlags(0x2b6c, &styleFlags1);
  MapUiThemeCodeToStyleFlags(0x2b6a, &styleFlags2);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b6c);

  short currentY = 0;
  if (itemHeight + currentY < frameHeight38) {
    int startIdx = scrollOffset;
    TTextListItem* pItem = &items[startIdx];
    int idx = startIdx;

    while (idx < totalItems) {
      CString tempString(pItem->text);

      if (idx == selectedIndex) {
        g_pUiRuntimeContext->ApplyLegendSplitSlot34(5);

        CRect rect;
        rect.left = 0;
        rect.top = currentY;
        rect.right = frameWidth34;
        rect.bottom = currentY + itemHeight;

        FillRectWithQuickDrawBrushAndContextOffset(&rect);
      }

      short textWidth = MeasureTextExtentWithCachedQuickDrawStyle(&tempString);
      short textX = static_cast<short>(frameWidth34 / 2) - static_cast<short>(textWidth / 2);

      SetQuickDrawColorAndSyncGlobals(styleFlags2);
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(textX + 1),
                                              static_cast<short>(currentY + 12));
      DrawTextWithCachedQuickDrawStyleState(&tempString);

      SetQuickDrawColorAndSyncGlobals(styleFlags1);
      SetQuickDrawTextOriginWithContextOffset(textX, static_cast<short>(currentY + 11));
      DrawTextWithCachedQuickDrawStyleState(&tempString);

      currentY += itemHeight;
      idx++;
      pItem++;

      if (itemHeight + currentY >= frameHeight38) {
        break;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0057af20
void TTextList::BeginMouseCaptureAndStartRepeatTimer(const CPoint& point, TToolboxEvent* event,
                                                     CPoint origin) {
  (void)event;
  (void)origin;

  int index = (point.y / itemHeight) + scrollOffset;
  if (index < totalItems) {
    selectedIndex = index;

    RefreshControl(); // slot 0x39 (was facade OnSelectionChangeSlotE4)

    CRect rect;
    QueryBounds(&rect); // slot 0x4b (was facade GetRectSlot12C)

    RECT localRect;
    CopyRect(&localRect, &rect);

    ownerContext->InvalidateCityDialogRectRegion(&localRect, 1);
    InvokeSlot13C(); // slot 0x4f (was facade OnSelectionConfirmedSlot13C)

    ownerContext->DispatchEvent(4, this, 0);
  }
}
