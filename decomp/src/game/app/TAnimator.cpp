#include "game/gfx/TAmbitApplication.h"
#include "game/app/TAnimator.h"

#include "game/ui_core/CIterator.h"
#include "game/app/TAnimation.h"
#include "game/ui_core/TApplication.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/TList.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/quickdraw_regions.h"
#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeObservation.h"
#include "RuntimeTestDriver.h"
#endif

IMPLEMENT_DYNCREATE(TAnimator, TEventHandler)

// FUNCTION: IMPERIALISM 0x004a0aa0
TAnimator::TAnimator()
    : TEventHandler(), renderSurfaceContext(0), registryList(0), mapUberPicture2c(0) {}

// FUNCTION: IMPERIALISM 0x004a0b20
void TAnimator::IAnimator(int idleFrequency) {
  IEventHandler(nullptr);
  idleFrequencyTicks = idleFrequency;
  RECT bounds;
  bounds.left = 0;
  bounds.top = 0;
  bounds.right = g_ptUiAnimatorSurfaceBounds.x;
  bounds.bottom = g_ptUiAnimatorSurfaceBounds.y;
  g_pDisplayMgr->MakeNewGWorld(renderSurfaceContext, 8, bounds);
  registryList = new TList();
  overlayPhaseTickCount = 0;
}

// FUNCTION: IMPERIALISM 0x004a0c00
void TAnimator::Install() {
  g_pAmbitApplication->InstallCohandler(this, true);
  SetIdleFreq(2);
}

// FUNCTION: IMPERIALISM 0x004a0c30
char TAnimator::DoIdle(int action) {
  if (action == 1) {
    if (mapUberPicture2c != 0 && mapUberPicture2c->HasActiveMapInteractionSelection()) {
      ++overlayPhaseTickCount;
      if (overlayPhaseTickCount >= 15) {
        mapUberPicture2c->PrepareAndRenderMapOverlayMode(g_bStrategicMapSelectionOverlayPhase);
        g_bStrategicMapSelectionOverlayPhase = !g_bStrategicMapSelectionOverlayPhase;
        overlayPhaseTickCount = 0;
      }
    }
  }

  if (action == 1) {
    CIterator cursor(registryList);
    TAnimation* animation = static_cast<TAnimation*>(cursor.Reset());
    while (cursor.More()) {
      animation->Tick();
      animation = static_cast<TAnimation*>(cursor.Advance());
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a0d10
void TAnimator::AddAnimation(TAnimation* animationObject) {
  registryList->AddTail(animationObject);
#ifdef IMPERIALISM_RUNTIME_TESTS
  RuntimeTestDriver::ObserveDeferred(kObserveAnimationAdded);
#endif
}

// FUNCTION: IMPERIALISM 0x004a0d30
TAnimation* TAnimator::FindRegisteredAnimationByTag(int tag) {
  if (this != 0) {
    CIterator cursor(registryList);
    TAnimation* animation = static_cast<TAnimation*>(cursor.Reset());
    while (cursor.More() && animation->registryTag != tag) {
      animation = static_cast<TAnimation*>(cursor.Advance());
    }
    if (animation != 0 && animation->registryTag == tag) {
      return animation;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a0dc0
void TAnimator::Free() {
  g_pAmbitApplication->InstallCohandler(this, false);
  if (registryList != 0) {
    registryList->FreePayloadsAndDestroy();
  }
  g_pDisplayMgr->RemoveGWorld(renderSurfaceContext);
  TEventHandler::Free();
}

// FUNCTION: IMPERIALISM 0x004a0e10
void TAnimator::ReadFrom(TStream* stream) {
  mapUberPicture2c = 0;
  idleFrequencyTicks = 0x7fffffff;
  idleFrequencyTicks = stream->ReadLong();
  TObject::ReadFrom(stream);
}

// FUNCTION: IMPERIALISM 0x004a0e50
void TAnimator::WriteTo(TStream* stream) {
  stream->WriteLong(idleFrequencyTicks);
  TObject::WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x004a0e90
void TAnimator::TranslateListRectsAndDropNonIntersectingEntries(int dx, int dy, RECT clipRect) {
  if (this != 0) {
    CIterator cursor(registryList);
    TAnimation* entry = static_cast<TAnimation*>(cursor.Reset());
    while (cursor.More()) {
      entry->screenRect.left += dx;
      entry->screenRect.top += dy;
      entry->screenRect.right += dx;
      entry->screenRect.bottom += dy;
      RECT scratch;
      if (!SectRect(&entry->screenRect, &clipRect, &scratch)) {
        CPtrList* list = &registryList->listState;
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
void TAnimator::FreeAllAnis() {
  if (this != 0) {
    registryList->FreePayloads();
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeTestDriver::ObserveDeferred(kObserveAnimationRemoved);
#endif
  }
}

// FUNCTION: IMPERIALISM 0x004a0fa0
void TAnimator::RemoveUiTransientRegistryObjectByTag(int tag) {
  TAnimation* animation = FindRegisteredAnimationByTag(tag);
  if (animation != 0) {
    POSITION pos = registryList->listState.Find(animation, 0);
    if (pos != 0) {
      registryList->listState.RemoveAt(pos);
    }
    animation->Free();
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeTestDriver::ObserveDeferred(kObserveAnimationRemoved);
#endif
  }
}
