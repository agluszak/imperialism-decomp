#include "game/TRadioTextCluster.h"

#include "game/TRadioText.h"
#include "game/ui_control_tags.h"
// SYNTHETIC: IMPERIALISM 0x005795b0
// TRadioTextCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00579680
// TRadioTextCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRadioTextCluster, TCluster)

// FUNCTION: IMPERIALISM 0x005796a0
TRadioTextCluster::TRadioTextCluster() : TCluster() {
  word8C = 0x4b;
  word8E = 0x49;
  selectedOption90 = -1;
  word92 = 0;
  word94 = 2;
}

// SYNTHETIC: IMPERIALISM 0x005796f0
// TRadioTextCluster::`scalar deleting destructor'
TRadioTextCluster::~TRadioTextCluster() {}

// FUNCTION: IMPERIALISM 0x00579740
void TRadioTextCluster::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x00579770
void TRadioTextCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xd) {
    SetSelectedTextOptionByTag(sourceHandler->controlTag, true);
  }
  TCluster::HandleEvent(commandId, sourceHandler, event);
}

// Syncs selectedTag88 to `tag`, then walks childList44 marking the TRadioText child whose
// controlTag matches as selected (isSelectedOption98) and clearing the others, refreshing
// each child whose selection state changed (only when refreshOnChange is set).
// FUNCTION: IMPERIALISM 0x005797c0
void TRadioTextCluster::SetSelectedTextOptionByTag(int tag, bool refreshOnChange) {
  if (selectedTag88 == tag) {
    return;
  }
  if (tag != static_cast<int>(kTagNada) && ResolveControlByTag(tag) == 0) {
    return;
  }
  selectedTag88 = tag;
  if (childList44 == 0) {
    return;
  }
  POSITION pos = childList44->GetHeadPosition();
  while (pos != NULL) {
    TRadioText* child = static_cast<TRadioText*>(childList44->GetNext(pos));
    child->AssertValid();
    bool shouldBeSelected = (child->controlTag == selectedTag88);
    if (shouldBeSelected != (child->isSelectedOption98 != 0)) {
      child->isSelectedOption98 = shouldBeSelected;
      if (refreshOnChange) {
        child->RefreshControl();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00579a60
void TRadioTextCluster::ApplyRectSlot110(RECT* rectBuffer) {}
