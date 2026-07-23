#include "game/gfx/TAmbitApplication.h"
#include "game/app/TAnimator.h"

#include "game/ui_core/CIterator.h"
#include "game/app/TAnimation.h"
#include "game/ui_core/TApplication.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/TList.h"
#include "game/core/TStream.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/quickdraw_regions.h"
// SYNTHETIC: IMPERIALISM 0x004a09f0
// TAnimator::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a0a80
// TAnimator::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAnimator, TEventHandler)

// The original inlines the TEventHandler base construction (keeping only the shared
// field-defaults helper out-of-line) and does not touch field28; the recompile emits
// the real base-ctor call instead -- the usual accepted ctor-inlining divergence.
// FUNCTION: IMPERIALISM 0x004a0aa0
TAnimator::TAnimator()
    : TEventHandler(), renderSurfaceContext(0), registryList24(0), mapUberPicture2c(0) {}

// SYNTHETIC: IMPERIALISM 0x004a0ad0
// TAnimator::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004a0b00
TAnimator::~TAnimator() {}

// FUNCTION: IMPERIALISM 0x004a0b20
void TAnimator::InitializeUiTransientObjectRegistry(int idleFrequency) {
  InitializePacketHeaderFields_Tag20202020(0);
  field10 = idleFrequency;
  RECT bounds;
  bounds.left = 0;
  bounds.top = 0;
  bounds.right = g_nUiAnimatorSurfaceBoundsWidth;
  bounds.bottom = g_nUiAnimatorSurfaceBoundsHeight;
  g_pDisplayMgr->MakeNewGWorld(renderSurfaceContext, 8, bounds);
  registryList24 = new TList();
  field28 = 0;
}

// FUNCTION: IMPERIALISM 0x004a0c00
void TAnimator::Install() {
  g_pGlobalUiRootController->InstallCohandler(this, 1);
  SetIdleFreq(2);
}

// FUNCTION: IMPERIALISM 0x004a0c30
char TAnimator::DoIdle(int action) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a0d10
void TAnimator::AddObjectToUiTransientRegistry(TAnimation* animationObject) {
  registryList24->AddTail(animationObject);
}

// FUNCTION: IMPERIALISM 0x004a0d30
TAnimation* TAnimator::FindRegisteredAnimationByTag(int tag) {
  // The original null-checks the receiver: call sites invoke this on g_pUiAnimator
  // without guarding it.
  if (this != 0) {
    CIterator cursor(registryList24);
    TAnimation* animation = static_cast<TAnimation*>(cursor.Reset());
    while (cursor.More() && animation->registryTag18 != tag) {
      animation = static_cast<TAnimation*>(cursor.Advance());
    }
    if (animation != 0 && animation->registryTag18 == tag) {
      return animation;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a0dc0
void TAnimator::Free() {
  g_pGlobalUiRootController->InstallCohandler(this, 0);
  if (registryList24 != 0) {
    registryList24->FreePayloadsAndDestroy();
  }
  g_pDisplayMgr->RemoveGWorld(renderSurfaceContext);
  TEventHandler::Free();
}

// FUNCTION: IMPERIALISM 0x004a0e10
void TAnimator::ReadFrom(TStream* stream) {
  mapUberPicture2c = 0;
  field10 = 0x7fffffff;
  field10 = stream->streamSlot50();
  TObject::ReadFrom(stream);
}

// FUNCTION: IMPERIALISM 0x004a0e50
void TAnimator::WriteTo(TStream* stream) {
  stream->streamSlot8c(field10);
  TObject::WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x004a0e90
void TAnimator::TranslateListRectsAndDropNonIntersectingEntries(int dx, int dy, RECT clipRect) {
  // The original null-checks the receiver: the call site invokes this on g_pUiAnimator
  // without guarding it.
  if (this != 0) {
    CIterator cursor(registryList24);
    TAnimation* entry = static_cast<TAnimation*>(cursor.Reset());
    while (cursor.More()) {
      entry->screenRect1C.left += dx;
      entry->screenRect1C.top += dy;
      entry->screenRect1C.right += dx;
      entry->screenRect1C.bottom += dy;
      RECT scratch;
      if (!SectRect(&entry->screenRect1C, &clipRect, &scratch)) {
        CPtrList* list = &registryList24->listState;
        POSITION pos = list->Find(entry, 0);
        if (pos != 0) {
          list->RemoveAt(pos);
        }
        entry->Free();
      }
      entry = static_cast<TAnimation*>(cursor.Advance());
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a0f80
void TAnimator::FreeUiTransientRegistryPayloads() {
  if (this != 0) {
    registryList24->FreePayloads();
  }
}

// The original inlines FindRegisteredAnimationByTag here (same loop, including the
// receiver null-check); the recompile emits the real call instead.
// FUNCTION: IMPERIALISM 0x004a0fa0
void TAnimator::RemoveUiTransientRegistryObjectByTag(int tag) {
  TAnimation* animation = FindRegisteredAnimationByTag(tag);
  if (animation != 0) {
    POSITION pos = registryList24->listState.Find(animation, 0);
    if (pos != 0) {
      registryList24->listState.RemoveAt(pos);
    }
    animation->Free();
  }
}
