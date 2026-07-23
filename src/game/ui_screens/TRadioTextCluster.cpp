#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_tags_common.h"

#include "game/ui_screens/TRadioText.h"
#include "game/CSubViewIterator.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/quickdraw_rendering.h"
// SYNTHETIC: IMPERIALISM 0x005795b0
// TRadioTextCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00579680
// TRadioTextCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRadioTextCluster, TCluster)

// FUNCTION: IMPERIALISM 0x005796a0
TRadioTextCluster::TRadioTextCluster() : TCluster() {
  word8C = 0x4b;
  word8E = 0x49;
  frameThemeCode90 = -1;
  itemInset92 = 0;
  itemVerticalSpacing94 = 2;
}

// SYNTHETIC: IMPERIALISM 0x005796f0
// TRadioTextCluster::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00579720
TRadioTextCluster::~TRadioTextCluster() {}

// FUNCTION: IMPERIALISM 0x00579740
void TRadioTextCluster::DoPostCreate(int arg) {
  TCluster::DoPostCreate(arg);
  selectedTag88 = kControlTagNada;
}

// FUNCTION: IMPERIALISM 0x00579770
void TRadioTextCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xd) {
    SetSelectedTextOptionByTag(sourceHandler->controlTag, true);
  }
  TCluster::DoEvent(commandId, sourceHandler, event);
}

// Syncs selectedTag88 to `tag`, then walks childList44 marking the TRadioText child whose
// controlTag matches as selected (isSelectedOption98) and clearing the others, refreshing
// each child whose selection state changed (only when refreshOnChange is set).
// FUNCTION: IMPERIALISM 0x005797c0
void TRadioTextCluster::SetSelectedTextOptionByTag(int tag, bool refreshOnChange) {
  if (selectedTag88 == tag) {
    return;
  }
  if (tag != static_cast<int>(kControlTagNada) && ResolveControlByTag(tag) == 0) {
    return;
  }
  selectedTag88 = tag;
  // The original walks the children with the shared bidirectional cursor (which handles a
  // null childList44 internally), not a raw GetHeadPosition/GetNext loop.
  CSubViewIterator iter(this);
  TRadioText* child = static_cast<TRadioText*>(iter.FirstSubView());
  if (iter.MoreSubViews()) {
    do {
      child->AssertValid();
      // Original compares the raw isSelectedOption98 byte directly (cmp al,cl) -- it never
      // holds anything but 0/1, so no `!= 0` normalization is emitted.
      unsigned char shouldBeSelected =
          static_cast<unsigned char>(child->controlTag == selectedTag88);
      if (shouldBeSelected != child->isSelectedOption98) {
        child->isSelectedOption98 = shouldBeSelected;
        if (refreshOnChange) {
          child->RefreshControl();
        }
      }
      child = static_cast<TRadioText*>(iter.NextSubView());
    } while (iter.MoreSubViews());
  }
}

// FUNCTION: IMPERIALISM 0x005798a0
TRadioText* TRadioTextCluster::AddItem(unsigned long tag, int value, const char* text, int height,
                                       int bottom) {
  if (bottom == -1) {
    bottom = itemInset92;
    // The original accumulates the max child bottom via the shared cursor (which handles a
    // null childList44 internally), not a raw GetHeadPosition/GetNext loop.
    CSubViewIterator iter(this);
    TView* child = iter.FirstSubView();
    if (iter.MoreSubViews()) {
      do {
        child->AssertValid();
        int childBottom = child->ownerLocalY + child->frameHeight38 + itemVerticalSpacing94;
        if (childBottom > bottom) {
          bottom = childBottom;
        }
        child = iter.NextSubView();
      } while (iter.MoreSubViews());
    }
  }

  TRadioText* item = new TRadioText();
  int offset[2];
  int size[2];
  offset[0] = itemInset92;
  offset[1] = bottom;
  size[0] = frameWidth34 - itemInset92 * 2;
  size[1] = height;
  item->InitializeTextEntryBaseAndOptionalStringResource(this, offset, size, 5, 5, -1, 1);
  item->controlTag = static_cast<int>(tag);
  item->controlValue3c = value;
  CString itemText(text);
  item->SetTextAndMaybeRefresh(&itemText, 1);
  item->SetEnable(1);
  return item;
}

// FUNCTION: IMPERIALISM 0x00579a60
void TRadioTextCluster::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  if (frameThemeCode90 > -1) {
    RECT frame = {0, 0, frameWidth34, frameHeight38};
    g_pUiRuntimeContext->ApplyLegendSplitSlot34(frameThemeCode90);
    QDFrameRect(&frame);
    SetQuickDrawFillColor(0);
  }
}
