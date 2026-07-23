// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "game/TControl.h"
#include "game/mfc.h"
#include "game/TMapKey.h"
#include "game/quickdraw_regions.h"
#include "game/TMouseCaptureState.h"
#include "game/TTEView.h"
#include "game/TMovieView.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_tags_common.h"

#include <new>

// FUNCTION: IMPERIALISM 0x00429450
int TControl::GetEventNumber() {
  return eventNumber60;
}

// FUNCTION: IMPERIALISM 0x00429470
void TControl::AssertCityProductionGlobalStateInitialized(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
  if (g_McAppUiFlag_006A143C == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiHeaderPath_006943CC, 0x56f);
  }
}

// FUNCTION: IMPERIALISM 0x004294a0
char TControl::LogUnhandledDialogMethodAndReturnFalse() {
  TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiHeaderPath_006943CC, 0x58f);
  return 0;
}

// Slot 0x08 override (0x00435760): TControl cannot be cloned. The original asserts via
// the McAppUI invalidation thunk (file header path, line 0x594) and returns null.

// FUNCTION: IMPERIALISM 0x00435760
TObject* TControl::ShallowClone() {
  TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiHeaderPath_006943CC, 0x594);
  return 0;
}
// IMPLEMENT_DYNCREATE also emits `TControl::CreateObject`; the original copy at
// 0x48e430 has the TControl ctor inlined into it.
// SYNTHETIC: IMPERIALISM 0x0048e430
// TControl::CreateObject

// SYNTHETIC: IMPERIALISM 0x0048e500
// TControl::GetRuntimeClass

IMPLEMENT_DYNCREATE(TControl, TView)

// FUNCTION: IMPERIALISM 0x0048e520
TControl::TControl()
    : TView(), eventNumber60(1), controlState64(0), contentInsets68(0, 0, 0, 0),
      textStyle78(g_UiResourceEntryDefaultTextStyle) {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x0048e590
// TControl::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0048e640
void TControl::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)event;
  (void)origin;
  int startX = point.x;
  int startY = point.y;
  g_McAppMouseCaptureState.capturedControl = this;
  CWnd::FromHandle(::SetCapture(nativeWindow50->m_hWnd));
  g_McAppMouseCaptureState.startPoint.x = startX;
  g_McAppMouseCaptureState.startPoint.y = startY;
  g_McAppMouseCaptureState.lastPoint.x = startX;
  g_McAppMouseCaptureState.lastPoint.y = startY;
  g_McAppMouseCaptureState.currentPoint.x = startX;
  g_McAppMouseCaptureState.currentPoint.y = startY;
  TrackMouse(kTrackPhaseBegin, g_McAppMouseCaptureState.startPoint,
             g_McAppMouseCaptureState.lastPoint, g_McAppMouseCaptureState.currentPoint, 1);
  if (g_McAppUiMouseCaptureTimerId_006A1ADC == 0) {
    g_McAppUiMouseCaptureTimerId_006A1ADC = SetTimer(
        nativeWindow50->m_hWnd, 0xef, 0x11, NotifyGlobalCaptureOwnerState1WithCachedCoords);
  }
}

// FUNCTION: IMPERIALISM 0x0048e710
void TControl::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == kControlCommandHiliteOn) {
    HiliteState(1, 1);
    return;
  }
  if (commandId == kControlCommandHiliteOff) {
    HiliteState(0, 1);
    return;
  }
  if (commandId == kControlCommandHiliteToggle) {
    HiliteState(controlState64 == 0, 1);
    return;
  }
  TEventHandler* child = GetNextHandler();
  if (child != 0) {
    child->HandleEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x0048e7a0
void TControl::SetTextColorAndMaybeRefresh(const COLORREF* textColor, bool refreshNow) {
  textStyle78.textColor = *textColor;
  if (refreshNow) {
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x0048e7d0
void TControl::InstallTextStyle(const TextStyle& style, char refreshNow) {
  textStyle78 = style;
  if (refreshNow != 0) {
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x0048e810
void TControl::HiliteState(unsigned char enabledState, unsigned char refreshNow) {
  if (controlState64 != static_cast<unsigned char>(enabledState)) {
    controlState64 = static_cast<unsigned char>(enabledState);
    if (refreshNow) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048e850
void TControl::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, unsigned char commandFlag) {
  (void)startPoint;
  (void)previousPoint;
  (void)commandFlag;
  if (phase == kTrackPhaseBegin) {
    HiliteState(1, 1);
    return;
  }
  if (phase == kTrackPhaseUpdate) {
    HiliteState(PointInBoundsAndActionable(&currentPoint), 1);
    return;
  }
  if (phase == kTrackPhaseEnd && PointInBoundsAndActionable(&currentPoint) != 0) {
    if (eventNumber60 == 4) {
      HandleEvent(kControlCommandHiliteToggle, this, 0);
      HandleEvent(eventNumber60, this, 0);
      return;
    }
    if (eventNumber60 != 0xc) {
      HandleEvent(kControlCommandHiliteOff, this, 0);
      HandleEvent(eventNumber60, this, 0);
      return;
    }
    HandleEvent(kControlCommandHiliteOn, this, 0);
    HandleEvent(eventNumber60, this, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0048e940
char TControl::PointInBoundsAndActionable(CPoint* point) {
  CRect rect;
  QueryContentBounds(&rect);
  POINT p;
  p.x = point->x;
  p.y = point->y;
  return PtInRect(&rect, p);
}

// FUNCTION: IMPERIALISM 0x0048e980
void TControl::BuildInsetContentRect(CRect* boundsBuffer) {
  QueryContentBounds(boundsBuffer);
  boundsBuffer->DeflateRect(&contentInsets68);
}

// FUNCTION: IMPERIALISM 0x0048e9c0
void TControl::NoOpUiViewSlotHandler(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

// FUNCTION: IMPERIALISM 0x0048e9e0
void TControl::NoOpControlAction(int) {}

// The template-dialog modal helpers (PrepareAndCreateModalFromTemplate 0x0049d360 and
// FinalizeModalDialogAndRestoreOwnerFocus 0x0049d450) and the CDialog constructor
// (0x006050d0) are really MFC-dialog machinery on the CDialog-derived dialog classes, not
// on the TControl widget hierarchy. They live on TModalDialogBase
// (src/game/TModalDialogBase.cpp); 0x006050d0 is the LIBRARY CDialog::CDialog constructor.

// KNOWN ILT (retired): 0x004087fb is a 5-byte `jmp TControl::TControl` linker stub — not ported.

// FUNCTION: IMPERIALISM 0x004fcea0
void TControl::SetDiplomacyNationSelectionFilterAndRefreshRows(short selectedNation) {
  short pictureId;
  if (selectedNation <= 0) {
    pictureId = 0x1393;
  } else {
    short table[5] = {0, 2, 3, 0, 1};
    pictureId = 0x1394 + table[selectedNation];
  }

  TMapKey& mapKey = *static_cast<TMapKey*>(this);
  mapKey.viewMode90 = selectedNation;
  mapKey.SetPictureResourceIdAndRefresh(pictureId, 1);

  for (int i = 0; i < 7; i++) {
    TView* child = mapKey.ResolveControlByTag(kControlTagNam0 + i);
    child->AssertValid();
    child->SetEnabled(selectedNation == i, 0);
  }
}
// Real ctor: TControl::TControl @ 0x0048e520 (base via : TView()).

// FUNCTION: IMPERIALISM 0x0058e440
void TControl::SetEventNumber(int value) {
  eventNumber60 = value;
}

TControl::~TControl() {}
