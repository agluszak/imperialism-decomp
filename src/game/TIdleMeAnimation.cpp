#include "game/TIdleMeAnimation.h"

#include "game/TAnimator.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x004ac950
// TIdleMeAnimation::`scalar deleting destructor'
TIdleMeAnimation::~TIdleMeAnimation() {}
// SYNTHETIC: IMPERIALISM 0x004ac920
// TIdleMeAnimation::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ac9a0
// TIdleMeAnimation::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIdleMeAnimation, TAnimation)

// FUNCTION: IMPERIALISM 0x004ac9c0
void TIdleMeAnimation::InitializeIdleAnimation(TView* ownerView) {
  int tag = g_nIdleMeAnimationNextRegistryTag;
  g_nIdleMeAnimationNextRegistryTag = tag + 1;
  RECT rect;
  rect.left = 0;
  rect.top = 0;
  rect.right = 0;
  rect.bottom = 0;
  InitializeAnimation(ownerView, &rect, 0, 0, 0, tag);
  g_pUiAnimator->AddObjectToUiTransientRegistry(this);
}

// FUNCTION: IMPERIALISM 0x004aca60
void TIdleMeAnimation::Tick() {
  if (ownerView04->DoIdle(1) && this != 0) {
    g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(registryTag18);
  }
}
