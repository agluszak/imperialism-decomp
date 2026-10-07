#include "game/ui_core/TControl.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"
#include "game/diplomacy_ui/TMapKey.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/core/TMouseCaptureState.h"
#include "game/ui_core/TTEView.h"
#include "game/assets/TMovieView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

#include <new>

// FUNCTION: IMPERIALISM 0x00429450
int TControl::GetEventNumber() {
  return eventNumber;
}

// FUNCTION: IMPERIALISM 0x00429470
void TControl::AssertCityProductionGlobalStateInitialized(int arg1, int arg2) {
  if (g_McAppUiFlag_006A143C == 0) {
    ReportAssertionFailure(g_szMcAppUiHeaderPath, 0x56f);
  }
}

// FUNCTION: IMPERIALISM 0x004294a0
bool TControl::LogUnhandledDialogMethodAndReturnFalse() {
  ReportAssertionFailure(g_szMcAppUiHeaderPath, 0x58f);
  return false;
}

// TControl cannot be cloned: asserts and returns null.

// FUNCTION: IMPERIALISM 0x00435760
TObject* TControl::ShallowClone() {
  ReportAssertionFailure(g_szMcAppUiHeaderPath, 0x594);
  return 0;
}

IMPLEMENT_DYNCREATE(TControl, TView)

// FUNCTION: IMPERIALISM 0x0048e520
TControl::TControl()
    : TView(), eventNumber(1), controlState(0), contentInsets(0, 0, 0, 0),
      textStyle(g_UiResourceEntryDefaultTextStyle) {}

// FUNCTION: IMPERIALISM 0x0048e640
void TControl::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  int startX = point.x;
  int startY = point.y;
  g_McAppMouseCaptureState.capturedControl = this;
  CWnd::FromHandle(::SetCapture(nativeWindow->m_hWnd));
  g_McAppMouseCaptureState.startPoint.x = startX;
  g_McAppMouseCaptureState.startPoint.y = startY;
  g_McAppMouseCaptureState.lastPoint.x = startX;
  g_McAppMouseCaptureState.lastPoint.y = startY;
  g_McAppMouseCaptureState.currentPoint.x = startX;
  g_McAppMouseCaptureState.currentPoint.y = startY;
  TrackMouse(kTrackPhaseBegin, g_McAppMouseCaptureState.startPoint,
             g_McAppMouseCaptureState.lastPoint, g_McAppMouseCaptureState.currentPoint, true);
  if (g_McAppUiMouseCaptureTimerId == 0) {
    g_McAppUiMouseCaptureTimerId =
        SetTimer(nativeWindow->m_hWnd, 0xef, 0x11, NotifyGlobalCaptureOwnerState1WithCachedCoords);
  }
}

// FUNCTION: IMPERIALISM 0x0048e710
void TControl::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == kControlCommandHiliteOn) {
    HiliteState(1, true);
    return;
  }
  if (commandId == kControlCommandHiliteOff) {
    HiliteState(0, true);
    return;
  }
  if (commandId == kControlCommandHiliteToggle) {
    HiliteState(controlState == 0, true);
    return;
  }
  TEventHandler* child = GetNextHandler();
  if (child != 0) {
    child->HandleEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x0048e7a0
void TControl::SetTextColorAndMaybeRefresh(const COLORREF* textColor, bool refreshNow) {
  textStyle.textColor = *textColor;
  if (refreshNow) {
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x0048e7d0
void TControl::InstallTextStyle(const TextStyle& style, char refreshNow) {
  textStyle = style;
  if (refreshNow != 0) {
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x0048e810
void TControl::HiliteState(unsigned char enabledState, bool refreshNow) {
  if (controlState != static_cast<unsigned char>(enabledState)) {
    controlState = static_cast<unsigned char>(enabledState);
    if (refreshNow) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048e850
void TControl::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, bool commandFlag) {
  if (phase == kTrackPhaseBegin) {
    HiliteState(1, true);
    return;
  }
  if (phase == kTrackPhaseUpdate) {
    HiliteState(PointInBoundsAndActionable(&currentPoint), true);
    return;
  }
  if (phase == kTrackPhaseEnd && PointInBoundsAndActionable(&currentPoint) != 0) {
    if (eventNumber == 4) {
      HandleEvent(kControlCommandHiliteToggle, this, 0);
      HandleEvent(eventNumber, this, 0);
      return;
    }
    if (eventNumber != 0xc) {
      HandleEvent(kControlCommandHiliteOff, this, 0);
      HandleEvent(eventNumber, this, 0);
      return;
    }
    HandleEvent(kControlCommandHiliteOn, this, 0);
    HandleEvent(eventNumber, this, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0048e940
char TControl::PointInBoundsAndActionable(CPoint* point) {
  CRect rect;
  GetExtent(&rect);
  POINT p;
  p.x = point->x;
  p.y = point->y;
  return PtInRect(&rect, p);
}

// FUNCTION: IMPERIALISM 0x0048e980
void TControl::BuildInsetContentRect(CRect* boundsBuffer) {
  GetExtent(boundsBuffer);
  boundsBuffer->DeflateRect(&contentInsets);
}

// FUNCTION: IMPERIALISM 0x0048e9c0
void TControl::NoOpUiViewSlotHandler(int arg1, int arg2) {}

// FUNCTION: IMPERIALISM 0x0048e9e0
void TControl::NoOpControlAction(int) {}

// FUNCTION: IMPERIALISM 0x00492e10
TControl::~TControl() {}

// FUNCTION: IMPERIALISM 0x004fcea0
void TControl::SetDiplomacyNationSelectionFilterAndRefreshRows(short selectedNation) {
  short table[5] = {0, 2, 3, 0, 1};

  TMapKey& mapKey = *static_cast<TMapKey*>(this);
  mapKey.viewMode = selectedNation;
  mapKey.SetPictureRsrcID(
      selectedNation <= 0 ? 0x1393 : static_cast<short>(0x1394 + table[selectedNation]), 1);

  bool enabled = selectedNation == 0;
  for (int i = 0; i < 7; i++) {
    TView* child = mapKey.FindSubView(kControlTagNam0 + i);
    child->AssertValid();
    child->Show(enabled, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0058e440
void TControl::SetEventNumber(int value) {
  eventNumber = value;
}
