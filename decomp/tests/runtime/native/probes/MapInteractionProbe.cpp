#include "MapInteractionProbe.h"

#include "game/map_ui/TMapDialog.h"
#include "game/ui_core/TWindow.h"

namespace {

HWND MapHost(TMapDialog* mapDialog) {
  if (mapDialog == 0 || mapDialog->nativeWindow50 == 0) {
    return 0;
  }
  return mapDialog->nativeWindow50->m_hWnd;
}

CPoint ToHostPoint(TMapDialog* mapDialog, const CPoint& localPoint) {
  return CPoint(localPoint.x + mapDialog->absoluteX, localPoint.y + mapDialog->absoluteY);
}

} // namespace

bool MapInteractionProbe::HoverAtLocalPoint(TMapDialog* mapDialog, const CPoint& localPoint) {
  HWND host = MapHost(mapDialog);
  if (host == 0) {
    return false;
  }
  // The classifier returns early while the pointer is still in the band it last resolved, so a
  // stale band swallows the hover and the caller reads the previous cursor.
  mapDialog->activeRegionBand = -1;
  const CPoint hostPoint = ToHostPoint(mapDialog, localPoint);
  SendMessageA(host, WM_MOUSEMOVE, 0, MAKELPARAM(hostPoint.x, hostPoint.y));
  return true;
}

bool MapInteractionProbe::HoverAcrossLocalPoints(TMapDialog* mapDialog,
                                                 const CPoint& firstLocalPoint,
                                                 const CPoint& secondLocalPoint) {
  HWND host = MapHost(mapDialog);
  if (host == 0) {
    return false;
  }
  mapDialog->activeRegionBand = -1;
  const CPoint firstHostPoint = ToHostPoint(mapDialog, firstLocalPoint);
  const CPoint secondHostPoint = ToHostPoint(mapDialog, secondLocalPoint);
  SendMessageA(host, WM_MOUSEMOVE, 0, MAKELPARAM(firstHostPoint.x, firstHostPoint.y));
  SendMessageA(host, WM_MOUSEMOVE, 0, MAKELPARAM(secondHostPoint.x, secondHostPoint.y));
  return true;
}
