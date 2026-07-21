#include "game/TScroller.h"

#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x0048ca60
// TScroller::CreateObject

// SYNTHETIC: IMPERIALISM 0x0048cb90
// TScroller::GetRuntimeClass

IMPLEMENT_DYNCREATE(TScroller, TView)

TScroller::TScroller() : TView() {}

// SYNTHETIC: IMPERIALISM 0x0048cad0
// TScroller::`scalar deleting destructor'
TScroller::~TScroller() {}

// FUNCTION: IMPERIALISM 0x0048cbb0
void TScroller::InitializeScrollerPlacement(TView* owner, int* offsetLayout, int* sizeLayout) {
  TView* inheritedResourceContext = 0;
  if (owner != 0) {
    inheritedResourceContext = owner->resourceContext;
    if (owner != 0) {
      nativeWindow50 = owner->nativeWindow50;
    }
  }
  controlTag = 0x20202020; // '    '
  field04 = 1;
  field08 = 1;
  linkedChildHandler = owner;
  ownerLocalX = offsetLayout[0];
  ownerLocalY = offsetLayout[1];
  frameWidth34 = sizeLayout[0];
  frameHeight38 = sizeLayout[1];
  if (owner != 0) {
    owner->AttachChildControl(this, 0);
  }
  resourceContext = inheritedResourceContext;
}
