#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_tags_common.h"

#include "game/ui_screens/TRadioText.h"
#include "game/CSubViewIterator.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/quickdraw_rendering.h"

IMPLEMENT_DYNCREATE(TRadioTextCluster, TCluster)

// FUNCTION: IMPERIALISM 0x005796a0
TRadioTextCluster::TRadioTextCluster() : TCluster() {
  selectedColorCode = 0x4b;
  unselectedColorCode = 0x49;
  frameThemeCode = -1;
  itemInset = 0;
  itemVerticalSpacing = 2;
}

// FUNCTION: IMPERIALISM 0x00579720
TRadioTextCluster::~TRadioTextCluster() {}

// FUNCTION: IMPERIALISM 0x00579740
void TRadioTextCluster::DoPostCreate(int arg) {
  TCluster::DoPostCreate(arg);
  selectedTag = kControlTagNada;
}

// FUNCTION: IMPERIALISM 0x00579770
void TRadioTextCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xd) {
    SetSelectedTextOptionByTag(sourceHandler->controlTag, true);
  }
  TCluster::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x005797c0
void TRadioTextCluster::SetSelectedTextOptionByTag(int tag, bool refreshOnChange) {
  if (selectedTag == tag) {
    return;
  }
  if (tag != static_cast<int>(kControlTagNada) && FindSubView(tag) == 0) {
    return;
  }
  selectedTag = tag;
  CSubViewIterator iter(this);
  TRadioText* child = static_cast<TRadioText*>(iter.FirstSubView());
  if (iter.MoreSubViews()) {
    do {
      child->AssertValid();
      bool shouldBeSelected = static_cast<unsigned char>(child->controlTag == selectedTag);
      if (shouldBeSelected != child->isSelectedOption) {
        child->isSelectedOption = shouldBeSelected;
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
    bottom = itemInset;
    CSubViewIterator iter(this);
    TView* child = iter.FirstSubView();
    if (iter.MoreSubViews()) {
      do {
        child->AssertValid();
        int childBottom = child->ownerLocalY + child->frameHeight + itemVerticalSpacing;
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
  offset[0] = itemInset;
  offset[1] = bottom;
  size[0] = frameWidth - itemInset * 2;
  size[1] = height;
  item->IStaticText(this, offset, size, 5, 5, -1, 1);
  item->controlTag = static_cast<int>(tag);
  item->controlValue = value;
  CString itemText(text);
  item->SetTextAndMaybeRefresh(&itemText, true);
  item->SetEnable(1);
  return item;
}

// FUNCTION: IMPERIALISM 0x00579a60
void TRadioTextCluster::Draw(RECT* rectBuffer) {
  if (frameThemeCode > -1) {
    RECT frame = {0, 0, frameWidth, frameHeight};
    g_pViewMgr->SetForeColor(frameThemeCode);
    QDFrameRect(&frame);
    SetQuickDrawFillColor(0);
  }
}
