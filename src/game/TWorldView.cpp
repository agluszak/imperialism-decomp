#include "game/TAmbitApplication.h"
#include "game/TWindow.h"
#include "game/TWorldView.h"

#include "game/TApplication.h"
#include "game/TArmyMgr.h"
#include "game/TCivMgr.h"
#include "game/TCivUnit.h"
#include "game/mfc.h"
#include "game/CTemporaryRegion.h"
#include "game/TEvent.h"
#include "game/TGlobalMapState.h"
#include "game/TMapMgr.h"
#include "game/TMapUberPicture.h"
#include "game/mapped_flavor_text.h"
#include "game/TNavyMgr.h"
#include "game/TOcean.h"
#include "game/TToolBarCluster.h"
#include "game/TUiEvent.h"
#include "game/TViewMgr.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/TSimMgr.h"
#include "game/TTaskForce.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

#include <new>

// 0x005c3b40 -- genuine __cdecl free thunk taking one int (ret 0, caller cleans); the
// typed cast at the call site only adjusts the void stub's argument type.
undefined4 Function_005c3b40(void);
void NormalizeWrappedMapCoord108x60(short* xCoord, short* yCoord);

// FUNCTION: IMPERIALISM 0x00519af0
short TWorldView::QueryMinusOneWordSlot77() {
  return -1;
}

// FUNCTION: IMPERIALISM 0x00594fc0
void TWorldView::CenterOn(int tileIndex) {
  (void)tileIndex;
}
// SYNTHETIC: IMPERIALISM 0x00594f20
// TWorldView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00594fe0
// TWorldView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TWorldView, TView)

// FUNCTION: IMPERIALISM 0x00595000
TWorldView::TWorldView() {
  hoveredTileIndex6c = 0;
  paintedHoverTileIndex6e = 0;
  field68 = 0;
  field6a = 0;
  stridedCellRecord7a = 0xffff;
}

// SYNTHETIC: IMPERIALISM 0x00595040
// TWorldView::`scalar deleting destructor'
TWorldView::~TWorldView() {}

// FUNCTION: IMPERIALISM 0x00595090
void TWorldView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x005950b0
void TWorldView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00595130
void TWorldView::ForwardParam(int param) {
  TKeyCommandEvent* commandEvent = reinterpret_cast<TKeyCommandEvent*>(param);
  CString message;

  switch (commandEvent->commandCode) {
  case 0x1b:
    DispatchUiRuntimeMessage102CAndRefreshActiveView();
    return;

  case 'P':
  case 'p': {
    CString searchText(g_szEmptyString);
    CString prompt;
    g_pSimMgr->GetString(0x2758, 0xb, &prompt);
    g_pUiRuntimeContext->MakePlanetSeedDialog(static_cast<LPCSTR>(prompt), searchText, 0, 0, 0, 0);

    for (int cityIndex = 0; cityIndex < 0x180; ++cityIndex) {
      CString cityName;
      g_pGlobalMapState->AssignCityRecordDisplayName(cityIndex, &cityName);
      if (_mbscmp(reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(searchText)),
                  reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(cityName))) == 0) {
        CenterOn(g_pGlobalMapState->cityScoreTable[cityIndex].cityTileIndex04);
        return;
      }
    }

    if (_mbscmp(reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(searchText)),
                reinterpret_cast<const unsigned char*>(g_szEmptyString)) != 0) {
      CString notFoundTemplate;
      g_pSimMgr->GetString(0x2758, 0xd, &notFoundTemplate);
      scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(notFoundTemplate),
                             static_cast<LPCSTR>(searchText));
      g_pUiRuntimeContext->ModalMessage(message, g_ptMapModeModalMessage, 0, 0);
    }
    return;
  }

  case 'O':
  case 'o': {
    CString searchText(g_szEmptyString);
    CString prompt;
    g_pSimMgr->GetString(0x2758, 0xc, &prompt);
    g_pUiRuntimeContext->MakePlanetSeedDialog(static_cast<LPCSTR>(prompt), searchText, 0, 0, 0, 0);

    for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
      CString zoneName;
      zone->AssignZoneDisplayNameToOutputRef(&zoneName);
      if (_mbscmp(reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(searchText)),
                  reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(zoneName))) == 0) {
        CenterOn(static_cast<short>(zone->tileOrTerrainId0c));
        return;
      }
    }

    if (_mbscmp(reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(searchText)),
                reinterpret_cast<const unsigned char*>(g_szEmptyString)) != 0) {
      CString notFoundTemplate;
      g_pSimMgr->GetString(0x2758, 0xe, &notFoundTemplate);
      scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(notFoundTemplate),
                             static_cast<LPCSTR>(searchText));
      g_pUiRuntimeContext->ModalMessage(message, g_ptMapModeModalMessage, 0, 0);
    }
    return;
  }

  case 'W':
  case 'w':
    g_pSelectedCivilianOrderState->ClearNationCivilianActionModesAndCycleSelection(
        g_pSimMgr->GetActiveNationId());
    return;

  case 'N':
  case 'n':
    g_pMapContextActionManager->ClearNationArmyActionModesAndCycleSelection(
        g_pSimMgr->GetActiveNationId());
    return;

  case 'A':
  case 'a':
    g_pNavyOrderManager->FreeShipsOf(g_pSimMgr->GetActiveNationId());
    return;

  case 'X':
  case 'x':
    CenterOn(
        g_pGlobalMapState->ComputeRepresentativeTileIndexForNation(g_pSimMgr->GetActiveNationId()));
    return;

  case 'Z':
  case 'z': {
    TMapUberPicture* mapView = static_cast<TMapUberPicture*>(ownerContext);
    if (mapView->invalidationFlag94 != 0) {
      mapView->CommitPendingUiModeChangeAndRefreshViews(0);
    } else {
      mapView->EnterMapInteractionOverlayMode(0);
    }
    return;
  }

  case 'C':
  case 'c':
    ownerContext->DoMenuCommand(0x406);
    return;

  default:
    break;
  }

  switch (static_cast<char>(commandEvent->commandCode)) {
  case 't':
    g_pUiRuntimeContext->ShowCivilianLedgerDialogAndSelectUnit();
    break;
  case 'u':
    g_pUiRuntimeContext->ShowArmyRosterDialogAndActivateProvinceSelection();
    break;
  case 'v':
    g_pUiRuntimeContext->ShowNavyRosterDialogAndApplySelection();
    break;
  }
}

// FUNCTION: IMPERIALISM 0x00595810
void TWorldView::DoSetCursor(CPoint* point, RgnHandle hitArg) {
  short cursorId = static_cast<short>(GetCursorID());
  if (cursorId != -1) {
    CPoint mappedPoint = ViewToQDPt(point);
    if (PtInRgn(&mappedPoint, hitArg) != 0) {
      SetCursor(g_pUiRuntimeContext->turnEventCursors[cursorId - TViewMgr::kCursorResourceIdBase]);
      return;
    }
  }
  SetCursor(LoadCursorA(0, IDC_ARROW));
}

// FUNCTION: IMPERIALISM 0x005958b0
void TWorldView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                     RgnHandle hitArg) {
  (void)hitArg;

  short cursorToken = -1;
  short tileRow = 0;
  short tileColumn = 0;
  short* hoverBand = &hoverRegionBand70;
  ConvertPoint(*point, tileRow, tileColumn, *hoverBand);
  hoveredTileIndex6c = static_cast<unsigned short>(
      ComputeStridedRecordAddress6C(static_cast<int>(tileRow), static_cast<int>(tileColumn)));

  // Skip the cursor recompute when neither the tile cell nor the region band changed
  // since the cursor was last rendered (activeRegionBand72 holds that last band; a click
  // cycles it out of range to force this dedup to miss and the cursor to refresh).
  if (hoveredTileIndex6c == paintedHoverTileIndex6e && *hoverBand == activeRegionBand72) {
    return;
  }

  short tileIndex = static_cast<short>(hoveredTileIndex6c);
  field68 =
      static_cast<unsigned short>(g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex);
  short interactionMode = static_cast<TMapUberPicture*>(ownerContext)->activeUnitCategoryIndex96;

  switch (interactionMode) {
  case 0:
    cursorToken = static_cast<short>(
        g_pMapContextActionManager->LookupMapCursorTokenByStateIndex(tileIndex, *hoverBand));
    if (cursorToken == 0) {
      cursorToken = static_cast<short>(
          g_pNavyOrderManager->GetMapContextActionLabelTokenByActionCode(tileIndex, *hoverBand));
    }
    if (cursorToken == 0) {
      cursorToken = static_cast<short>(
          g_pSelectedCivilianOrderState->LookupCivilianTileOrderCursorTokenByActionIndex(
              tileIndex, *hoverBand));
    }
    break;

  case 1:
    cursorToken = static_cast<short>(
        g_pMapContextActionManager->LookupMapCursorTokenByStateIndex(tileIndex, *hoverBand));
    if (cursorToken == 0) {
      cursorToken = static_cast<short>(
          g_pSelectedCivilianOrderState->ResolveCivilianTileSelectionOrReportActionCode(
              tileIndex, *hoverBand));
    }
    if (cursorToken == 0) {
      cursorToken = static_cast<short>(
          g_pNavyOrderManager->GetMapContextActionLabelTokenByActionCode(tileIndex, *hoverBand));
    }
    if (cursorToken == 0) {
      cursorToken =
          static_cast<short>(g_pMapContextActionManager->LookupCivilianMapCursorTokenByStateIndex(
              tileIndex, *hoverBand));
    }
    break;

  case 2:
    cursorToken = static_cast<short>(
        g_pMapContextActionManager->LookupMapCursorTokenByStateIndex(tileIndex, *hoverBand));
    if (cursorToken == 0) {
      cursorToken = static_cast<short>(
          g_pSelectedCivilianOrderState->ResolveCivilianTileSelectionOrReportActionCode(
              tileIndex, *hoverBand));
    }
    if (cursorToken == 0) {
      cursorToken = static_cast<short>(
          g_pNavyOrderManager->GetMapContextActionLabelToken(tileIndex, *hoverBand));
    }
    break;

  case 4:
    if (g_pGlobalMapState->terrainStateTable[tileIndex].recruitSearchVisited0e == 0) {
      cursorToken = 0x3eb;
    }
    break;

  default:
    cursorToken = static_cast<short>(
        g_pMapContextActionManager->LookupMapCursorTokenByStateIndex(tileIndex, *hoverBand));
    if (cursorToken == 0) {
      cursorToken = static_cast<short>(
          g_pSelectedCivilianOrderState->ResolveCivilianTileSelectionOrReportActionCode(
              tileIndex, *hoverBand));
    }
    if (cursorToken == 0) {
      cursorToken = static_cast<short>(
          g_pNavyOrderManager->GetMapContextActionLabelTokenByActionCode(tileIndex, *hoverBand));
    }
    break;
  }

  if (cursorToken == 0x3e7 || cursorToken == 0) {
    cursorToken = -1;
  }
  cursorId4e = static_cast<unsigned short>(cursorToken);

  HCURSOR cursor;
  if (cursorToken == -1) {
    cursor = LoadCursorA(0, MAKEINTRESOURCEA(0x7f00));
  } else {
    cursor = g_pUiRuntimeContext->turnEventCursors[cursorToken - 1000];
  }
  SetCursor(cursor);

  {
    ScopedMapQuickDrawContext scopedContext(this);
    if (hoveredTileIndex6c != paintedHoverTileIndex6e) {
      RenderStrategicTileSelectionAndNeighborHighlights();
    }
  }

  paintedHoverTileIndex6e = hoveredTileIndex6c;
  field6a = field68;
  activeRegionBand72 = *hoverBand;
}

// FUNCTION: IMPERIALISM 0x00595c40
void TWorldView::SetMapOverlayModeAndRenderPreview(unsigned char overlayMode) {
  overlayFlagByte74 = overlayMode;
  RenderMapContextOverlayWithScopedClipAndSurface();
}

// The original's overlay dispatches all go through THIS view's own vtable
// (`MOV EDI,[ESI]` then `MOV ECX,ESI; CALL [EDI+0x128/0x1a8/0x1ac/0x1b0]` in the
// raw listing) -- plain self-virtual calls on the TWorldView, not calls through
// `ownerContext`'s table as a previous port assumed (that version faked the
// dispatches with __fastcall casts through the wrong object's vtable and dead-
// gated the mode-0 branch on a variable that was always -1 there). ownerContext
// is read only for its mode/context fields.
// FUNCTION: IMPERIALISM 0x00595c70
void TWorldView::RenderMapContextOverlayWithScopedClipAndSurface() {
  CTemporaryRegion reusableSurfaceA;
  CTemporaryRegion reusableSurfaceB;

  TMapUberPicture* mapUberPicture = static_cast<TMapUberPicture*>(ownerContext);
  short interactionMode = mapUberPicture->activeUnitCategoryIndex96;
  TCivUnit* selectedOrder = 0;
  short previewTile = -1;

  if (interactionMode == 0) {
    selectedOrder = g_pSelectedCivilianOrderState->selectedEntry;
    if (selectedOrder != 0) {
      previewTile = selectedOrder->tileIndex06;
    }
  } else if (interactionMode == 1) {
    short actionIndex = g_pMapContextActionManager->pendingMapActionIndex;
    if (actionIndex != -1) {
      previewTile = g_pGlobalMapState->cityScoreTable[actionIndex].cityTileIndex04;
    }
  } else if (interactionMode == 2) {
    int attachedEntity = 0;
    if (mapUberPicture->activeUnitCategoryIndex96 == 2) {
      attachedEntity = reinterpret_cast<int>(mapUberPicture->orderEntryContext98);
    }
    if (attachedEntity != 0) {
      previewTile = *reinterpret_cast<short*>(attachedEntity + 0x20);
    }
  }

  if (previewTile == -1) {
    return;
  }

  short outY = 0;
  short outX = 0;
  ForwardProjectTileIndexToWrappedScreenOffsetByScale(
      previewTile, reinterpret_cast<short*>(&viewportOffsetX), &outX, &outY, projectionScale76);

  GetClip(reusableSurfaceA.tempRgn);
  SetGlobalQuickDrawOrigin(static_cast<short>(absoluteX), static_cast<short>(absoluteY));

  // Preserve the original stack order: the projection routine's first output occupies
  // RECT::left and its second output occupies RECT::top.
  CRect previewRect(outY, outX, outY + previewSquareRadius78, outX + previewSquareRadius78);
  CRect contentBounds;
  QueryContentBounds(&contentBounds);
  SectRect(&previewRect, &contentBounds, &previewRect);

  CRect clipRect = previewRect;
  OffsetRect(&clipRect, absoluteX, absoluteY);

  ScopedMapQuickDrawContext scopedContext(this, &clipRect);
  RectRgn(reusableSurfaceB.tempRgn, &previewRect);
  SetClip(reusableSurfaceB.tempRgn);

  char regionPresent = EmptyRgn(reusableSurfaceB.tempRgn);
  if (regionPresent == 0) {
    // The mode-1/2 branches rebuild the projected square into one shared local
    // (the original recomputes it from outX/outY rather than reusing previewRect,
    // whose value SectRect clipped above).
    CRect badgeRect;
    if (interactionMode == 0) {
      RenderMapOrderEntryTilePreview(selectedOrder, outX, outY, 1, previewTile);
    } else if (interactionMode == 1) {
      badgeRect.SetRect(outY, outX, outY + previewSquareRadius78, outX + previewSquareRadius78);
      RenderTacticalStackCountIndicatorAndUnitBadge(previewTile, &badgeRect, 1);
    } else if (interactionMode == 2) {
      badgeRect.SetRect(outY, outX, outY + previewSquareRadius78, outX + previewSquareRadius78);
      RenderMapDialogTerrainOverlayFrameByTileOwner(previewTile, &badgeRect, 1);
    }
  }

  SetClip(reusableSurfaceA.tempRgn);
}

// FUNCTION: IMPERIALISM 0x00596020
void TWorldView::RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int projectedX,
                                                int projectedY, int flag, short tileIndex) {
  (void)orderEntry;
  (void)projectedX;
  (void)projectedY;
  (void)flag;
  (void)tileIndex;
}

// FUNCTION: IMPERIALISM 0x00596040
void TWorldView::RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, CRect* dstRect,
                                                               int flag) {
  (void)tileIndex;
  (void)dstRect;
  (void)flag;
}

// FUNCTION: IMPERIALISM 0x00596060
void TWorldView::RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, CRect* dstRect,
                                                               unsigned char altOverlay) {
  (void)tileIndex;
  (void)dstRect;
  (void)altOverlay;
}

// FUNCTION: IMPERIALISM 0x00596080
void TWorldView::RenderStrategicTileSelectionAndNeighborHighlights() {}

// FUNCTION: IMPERIALISM 0x005960a0
short TWorldView::QueryMinusOneWordSlot1BC(int unusedArg) {
  (void)unusedArg;
  return -1;
}

// FUNCTION: IMPERIALISM 0x005960c0
void TWorldView::ConvertPoint(const CPoint& point, short& outColumn, short& outRow,
                              short& outRegionBand) {
  (void)point;
  (void)outColumn;
  (void)outRow;
  (void)outRegionBand;
}

// FUNCTION: IMPERIALISM 0x005960e0
void TWorldView::ForwardProjectTileIndexToWrappedScreenOffsetByScale(int tileIndex,
                                                                     short* viewportOriginXY,
                                                                     short* outVerticalOffset,
                                                                     short* outHorizontalOffset,
                                                                     int projectionScale) {
  (void)tileIndex;
  (void)viewportOriginXY;
  (void)outVerticalOffset;
  (void)outHorizontalOffset;
  (void)projectionScale;
}

// FUNCTION: IMPERIALISM 0x00596100
char TWorldView::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)origin;

  CTemporaryRegion surface;

  short tileRow = 0;
  short tileCol = 0;
  short regionBand = 0;
  ConvertPoint(point, tileRow, tileCol, regionBand);
  NormalizeWrappedMapCoord108x60(&tileRow, &tileCol);

  int stridedRecord = ComputeStridedRecordAddress6C((int)tileRow, (int)tileCol);
  if (event->mouseButton24 == 1) {
    DispatchOverlayEvent78FromStridedRecord(stridedRecord, regionBand);
    return 1;
  }

  if (((unsigned short)GetAsyncKeyState(0x11) & 0x8000) != 0) {
    InvokeDialogHooks1D8ThenE4(stridedRecord, regionBand);
    return 1;
  }

  if (((unsigned short)GetAsyncKeyState(0x10) & 0x8000) != 0) {
    DispatchOverlayEvent78FromStridedRecord(stridedRecord, regionBand);
    return 1;
  }

  if (g_pGlobalUiRootController->screenModeAt24 < 2) {
    HandleMapClickByInteractionMode(static_cast<short>(stridedRecord), regionBand);
    return 1;
  }

  DispatchOverlayEvent78RootHighFromStridedRecord(stridedRecord, regionBand);
  return 1;
}

// FUNCTION: IMPERIALISM 0x00596270
void TWorldView::InvokeDialogHooks1D8ThenE4(int stridedRecord, int dispatchContext) {
  (void)stridedRecord;
  (void)dispatchContext;
  CenterOn(0);
  reinterpret_cast<TView*>(this)->TView::RefreshControl();
}

// FUNCTION: IMPERIALISM 0x005962a0
void TWorldView::HandleMapTileClickSetOrderContextAndHandleEvent79(int arg1, int arg2) {
  (void)arg2;
  TEvent* event = new TEvent();

  int tileIndex = static_cast<short>(arg1);
  char* terrainTable = reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable);
  if (terrainTable[tileIndex * 0x24] == '\x05') {
    // ILT thunk 0x40318e resolves to TOcean::GetLinkedZoneForSeaTile on the
    // g_pActiveMapOrderContext singleton (same call TToolBarCluster uses).
    TZone* orderContext =
        g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(static_cast<short>(tileIndex));
    // ownerContext is really a TMapUberPicture* (see the class-attribution note on
    // TMapUberPicture::SetMapInteractionMode); SetActiveMapOrderEntry already reproduces
    // this exact invalidate-old/set/invalidate-new/refresh sequence.
    static_cast<TMapUberPicture*>(ownerContext)->SetActiveMapOrderEntry(orderContext);
  }

  g_lastClickedMapTileIndex_006a4608 = tileIndex;
  // No null guard in the original: the field writes run through the raw allocation
  // pointer whether or not `new` succeeded.
  event->dispatchMessage = 0x79;
  event->commandNumber = 0x79;
  event->sourceHandler = this;
  event->targetHandler = this;
  DispatchQueuedUiCommandAndRelease(event);
}

// Build a TEvent carrying command/dispatch code 0x78, source/target = this view,
// stash the strided cell record in stridedCellRecord7a, and hand it to the slot-0xd dispatcher.
// The field writes intentionally run even when `new` returns null (the original
// writes through the raw allocation pointer unconditionally).
// FUNCTION: IMPERIALISM 0x005963d0
void TWorldView::DispatchOverlayEvent78FromStridedRecord(int stridedRecord, int dispatchContext) {
  (void)dispatchContext;
  TEvent* event = new TEvent();
  event->dispatchMessage = 0x78;
  event->commandNumber = 0x78;
  event->sourceHandler = this;
  event->targetHandler = this;
  stridedCellRecord7a = static_cast<unsigned short>(stridedRecord);
  DispatchQueuedUiCommandAndRelease(event);
}

// FUNCTION: IMPERIALISM 0x00596440
void TWorldView::DispatchOverlayEvent78RootHighFromStridedRecord(int stridedRecord,
                                                                 int dispatchContext) {
  (void)dispatchContext;
  TEvent* event = new TEvent();
  event->dispatchMessage = 0x78;
  event->commandNumber = 0x78;
  event->sourceHandler = this;
  event->targetHandler = this;
  stridedCellRecord7a = static_cast<unsigned short>(stridedRecord);
  DispatchQueuedUiCommandAndRelease(event);
}

// FUNCTION: IMPERIALISM 0x005964b0
void TWorldView::HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) {
  // Per active-unit-category interaction mode, offer the tile click to the map-context
  // (TArmyMgr), civilian-order (TCivMgr) and navy/map-order (g_pNavyOrderManager) handlers
  // in a mode-specific order. A handler that consumes the click either refreshes this view
  // or advances the owner's selection cycle; every call advances the active region-band
  // index (+0x72) 1..4, which also invalidates the hover handler's cursor-render dedup.
  char handled;
  switch (static_cast<TMapUberPicture*>(ownerContext)->activeUnitCategoryIndex96) {
  case 0:
    if (g_pMapContextActionManager->HandleMapClickByComputedCursorState(nTileIndex, nInputFlags) !=
            0 ||
        g_pNavyOrderManager->TryHandleMapContextAction(nTileIndex, nInputFlags) != 0) {
      goto refresh;
    }
    handled = g_pSelectedCivilianOrderState->HandleCivilianTileOrderAction(nTileIndex, nInputFlags);
    goto cycle;
  case 1:
    if (g_pMapContextActionManager->HandleMapClickByComputedCursorState(nTileIndex, nInputFlags) !=
            0 ||
        g_pSelectedCivilianOrderState->HandleCivilianTileSelectionOrReportClick(nTileIndex,
                                                                                nInputFlags) != 0 ||
        g_pNavyOrderManager->TryHandleMapContextAction(nTileIndex, nInputFlags) != 0) {
      goto refresh;
    }
    handled =
        g_pMapContextActionManager->HandleMapClickByCivilianCursorState(nTileIndex, nInputFlags);
    goto cycle;
  case 2:
    if (g_pMapContextActionManager->HandleMapClickByComputedCursorState(nTileIndex, nInputFlags) !=
            0 ||
        g_pSelectedCivilianOrderState->HandleCivilianTileSelectionOrReportClick(nTileIndex,
                                                                                nInputFlags) != 0) {
      goto refresh;
    }
    handled = static_cast<char>(
        g_pNavyOrderManager->TryQueueMapOrderFromTileAction(nTileIndex, nInputFlags));
    goto cycle;
  case 3:
    if (g_pMapContextActionManager->HandleMapClickByComputedCursorState(nTileIndex, nInputFlags) ==
            0 &&
        g_pSelectedCivilianOrderState->HandleCivilianTileSelectionOrReportClick(nTileIndex,
                                                                                nInputFlags) == 0) {
      g_pNavyOrderManager->TryHandleMapContextAction(nTileIndex, nInputFlags);
    }
    goto tail;
  default:
    goto tail;
  }
refresh:
  RefreshControl();
  goto tail;
cycle:
  if (handled != 0) {
    static_cast<TMapUberPicture*>(ownerContext)->CycleMapInteractionSelectionAfterHandledClick();
  }
tail:
  ++activeRegionBand72;
  if (activeRegionBand72 > 4) {
    activeRegionBand72 = 1;
  }
}

// FUNCTION: IMPERIALISM 0x00596680
void TWorldView::SetMapViewCellCoordinates(int column, int row) {
  (void)column;
  (void)row;
}

// FUNCTION: IMPERIALISM 0x005966a0
void TWorldView::SetMapViewTileIndex(int arg1) {
  (void)arg1;
}

// FUNCTION: IMPERIALISM 0x005966c0
void TWorldView::OrphanRetStub_005966c0(short arg1) {
  (void)arg1;
}

// FUNCTION: IMPERIALISM 0x005966e0
undefined TWorldView::OrphanLeaf_NoCall_Ins02_005966e0(short arg1) {
  (void)arg1;
  return 0;
}

// Shared slot-0xc6 (byte 0x1f0) body across the view classes: probe the map-dialog
// tile marker (slot 0x7b); if it reports nothing pending, refresh this view's marker
// (slot 0x76), then always refresh the owner view's marker through the same slot, run the
// owner panel's input-capture reset (slots 0x16 -> 0x4f), and spin the shifted-tick busy
// wait. ownerContext is typed TView*, but slot 0x76 lives in TView's vtable (null in the
// base, filled by derived views); the static_cast down to TWorldView selects that slot
// and compiles to the identical `call [vtable+0x1d8]`.
// FUNCTION: IMPERIALISM 0x00596700
void TWorldView::OrphanCallChain_C6_I29_00596700(int arg1) {
  if (OrphanLeaf_NoCall_Ins02_005966e0(static_cast<short>(arg1)) == 0) {
    CenterOn(arg1);
  }
  static_cast<TWorldView*>(ownerContext)->CenterOn(arg1);
  GetWindow()->ForceRedraw();
  reinterpret_cast<void(__cdecl*)(int)>(Function_005c3b40)(0x1e);
}
