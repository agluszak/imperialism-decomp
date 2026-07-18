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
#include "game/ScopedMapQuickDrawContext.h"
#include "game/TTaskForce.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

#include <new>

undefined4 thunk_GetMapActionContextByTileIndex(void);
void NormalizeWrappedMapCoord108x60(short* xCoord, short* yCoord);

// FUNCTION: IMPERIALISM 0x00519af0
short TWorldView::QueryMinusOneWordSlot77() {
  return -1;
}

// FUNCTION: IMPERIALISM 0x00594fc0
void TWorldView::UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1) {
  (void)arg1;
}
// SYNTHETIC: IMPERIALISM 0x00594f20
// TWorldView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00594fe0
// TWorldView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TWorldView, TView)

// FUNCTION: IMPERIALISM 0x00595000
TWorldView::TWorldView() {}

// SYNTHETIC: IMPERIALISM 0x00595040
// TWorldView::`scalar deleting destructor'
TWorldView::~TWorldView() {}

// FUNCTION: IMPERIALISM 0x00595090
void TWorldView::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);
}

// FUNCTION: IMPERIALISM 0x005950b0
void TWorldView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00595130
void TWorldView::ForwardParam(int param) {
  TEventHandler::ForwardParam(param);
}

// FUNCTION: IMPERIALISM 0x00595810
void TWorldView::HandleCursorHoverFallback(CPoint* point, RgnHandle hitArg) {
  TView::HandleCursorHoverFallback(point, hitArg);
}

// FUNCTION: IMPERIALISM 0x005958b0
void TWorldView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                     RgnHandle hitArg) {
  TView::HandleCursorHoverSelectionByChildHitTestAndFallback(point, hitArg);
}

// FUNCTION: IMPERIALISM 0x00595c40
void TWorldView::SetFlagByteAndInvokeVslot1A4(unsigned char flagByte) {
  field74 = flagByte;
  RenderMapContextOverlayWithScopedClipAndSurface();
}

// FUNCTION: IMPERIALISM 0x00595c70
void TWorldView::RenderMapContextOverlayWithScopedClipAndSurface() {
  CTemporaryRegion reusableSurfaceA;
  CTemporaryRegion reusableSurfaceB;

  TMapUberPicture* mapUberPicture = static_cast<TMapUberPicture*>(ownerContext);
  short interactionMode = mapUberPicture->activeUnitCategoryIndex96;
  int previewTileIndex = -1;
  short previewBand = -1;

  if (interactionMode == 0) {
    TCivUnit* selectedOrder = g_pSelectedCivilianOrderState->selectedEntry;
    if (selectedOrder != 0) {
      previewTileIndex = -1;
      previewBand = selectedOrder->tileIndex06;
    }
  } else if (interactionMode == 1) {
    short actionIndex = g_pMapContextActionManager->pendingMapActionIndex;
    if (actionIndex != -1) {
      previewBand = -1;
      previewTileIndex = g_pGlobalMapState->cityScoreTable[actionIndex].cityTileIndex04;
    }
  } else if (interactionMode == 2) {
    int attachedEntity = 0;
    if (mapUberPicture->activeUnitCategoryIndex96 == 2) {
      attachedEntity = reinterpret_cast<int>(mapUberPicture->orderEntryContext98);
    }
    if (attachedEntity != 0) {
      previewBand = -1;
      previewTileIndex = *reinterpret_cast<short*>(attachedEntity + 0x20);
    }
  }

  if (static_cast<short>(previewTileIndex) == -1) {
    return;
  }

  short outX = 0;
  short outY = 0;
  short outExtra = 0;
  short packedBand = previewBand;
  ForwardProjectTileIndexToWrappedScreenOffsetByScale(
      previewTileIndex, reinterpret_cast<int>(&viewportOffsetX), reinterpret_cast<int>(&outX),
      reinterpret_cast<int>(&outY), packedBand);

  GetClip(reusableSurfaceA.tempRgn);
  SetGlobalQuickDrawOrigin(static_cast<short>(absoluteX), static_cast<short>(absoluteY));

  short rectWidth = field76;
  short rectHeight = field78;
  short originX = outX;
  short originY = outY;
  short rectRight = originX + rectWidth;
  short rectBottom = originY + rectHeight;

  struct MapOverlayRect {
    long left;
    long top;
    long right;
    long bottom;
  } clipRect;
  // Slot 0x128 is TView::QueryContentBounds (0x4a); call it as the real virtual.
  mapUberPicture->QueryContentBounds(reinterpret_cast<RECT*>(&clipRect.bottom));

  // Slots 0x1ac/0x1b0 are polymorphic tile-preview renderers introduced by the concrete
  // map-view subclass that actually owns `ownerContext`: the caller passes 3 stack args,
  // but this branch's shared base slots (TControl's NoOpUiViewSlotHandler / OrphanRetStub
  // at bytes 0x1ac/0x1b0) are 2-arg/1-arg no-op placeholders, so no virtual declarable on
  // the TMapUberPicture static type has the right arity. Left as a documented raw dispatch
  // until that receiver subclass is recovered (raw-vtable-gate baselined).
  int childVtable = *reinterpret_cast<int*>(mapUberPicture);

  char intersectScratch[16];
  char intersectPair[16];
  SectRect(reinterpret_cast<RECT*>(&clipRect.left), reinterpret_cast<RECT*>(intersectScratch),
           reinterpret_cast<RECT*>(intersectPair));
  OffsetRect(reinterpret_cast<RECT*>(&clipRect), absoluteX, absoluteY);

  ScopedMapQuickDrawContext scopedContext(this, reinterpret_cast<RECT*>(&clipRect));
  RectRgn(reusableSurfaceB.tempRgn, reinterpret_cast<RECT*>(&clipRect.left));
  SetClip(reusableSurfaceB.tempRgn);

  char regionPresent = EmptyRgn(reusableSurfaceB.tempRgn);
  if (regionPresent == 0) {
    if (interactionMode == 0) {
      RenderMapOrderEntryTilePreview(g_pSelectedCivilianOrderState->selectedEntry, originX,
                                     outExtra);
    } else if (interactionMode == 1) {
      int previewArgs[4];
      previewArgs[0] = outExtra;
      previewArgs[1] = rectHeight;
      previewArgs[2] = originX;
      previewArgs[3] = rectRight;
      typedef void(__fastcall * ChildSlot1acFn)(void* self, int unusedEdx, int tile, void* rectArgs,
                                                int flag);
      reinterpret_cast<ChildSlot1acFn>(*reinterpret_cast<int*>(childVtable + 0x1ac))(
          mapUberPicture, 0, previewTileIndex, previewArgs, 1);
    } else if (interactionMode == 2) {
      int previewArgs[4];
      previewArgs[0] = outExtra;
      previewArgs[1] = rectHeight;
      previewArgs[2] = originX;
      previewArgs[3] = rectBottom;
      typedef void(__fastcall * ChildSlot1b0Fn)(void* self, int unusedEdx, int tile, void* rectArgs,
                                                int flag);
      reinterpret_cast<ChildSlot1b0Fn>(*reinterpret_cast<int*>(childVtable + 0x1b0))(
          mapUberPicture, 0, previewTileIndex, previewArgs, 1);
    }
  }

  SetClip(reusableSurfaceA.tempRgn);
}

// FUNCTION: IMPERIALISM 0x00596020
void TWorldView::RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int arg2, int arg3) {
  (void)orderEntry;
  (void)arg2;
  (void)arg3;
}

// FUNCTION: IMPERIALISM 0x00596040
void TWorldView::RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, int arg2,
                                                               int arg3) {
  (void)tileIndex;
  (void)arg2;
  (void)arg3;
}

// FUNCTION: IMPERIALISM 0x00596060
void TWorldView::RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                               unsigned char altOverlay) {
  (void)tileIndex;
  (void)dstRect;
  (void)altOverlay;
}

// FUNCTION: IMPERIALISM 0x00596080
void TWorldView::RenderStrategicTileSelectionAndNeighborHighlights() {}

// FUNCTION: IMPERIALISM 0x005960a0
short TWorldView::QueryMinusOneWordSlot1BC() {
  return -1;
}

// FUNCTION: IMPERIALISM 0x005960c0
void TWorldView::ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                   unsigned short* outCol,
                                                                   short* outBand) {
  (void)overlayRecord;
  (void)outRow;
  (void)outCol;
  (void)outBand;
}

// FUNCTION: IMPERIALISM 0x005960e0
void TWorldView::ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                     int arg4, int arg5) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  (void)arg5;
}

// FUNCTION: IMPERIALISM 0x00596100
char TWorldView::DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) {
  int overlayRecord = reinterpret_cast<int>(point);
  (void)arg2;
  (void)arg3;
  (void)arg4;

  CTemporaryRegion surface;

  short tileRow = 0;
  unsigned short tileCol = 0;
  short regionBand = 0;
  ComputeWrappedMapCellAndRegionBandFromScreenCoord(overlayRecord, &tileRow, &tileCol, &regionBand);
  NormalizeWrappedMapCoord108x60(&tileRow, reinterpret_cast<short*>(&tileCol));

  int stridedRecord = ComputeStridedRecordAddress6C((int)tileRow, (int)tileCol);
  if (*reinterpret_cast<int*>(overlayRecord + 0x24) == 1) {
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
  UpdateMapDialogTileRowColumnMarkerAndInvalidate(0);
  reinterpret_cast<TView*>(this)->TView::RefreshControl();
}

// FUNCTION: IMPERIALISM 0x005962a0
void TWorldView::HandleMapTileClickSetOrderContextAndDispatchEvent79(int arg1, int arg2) {
  (void)arg2;
  TEvent* event = new TEvent();

  int tileIndex = static_cast<short>(arg1);
  char* terrainTable = reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable);
  if (terrainTable[tileIndex * 0x24] == '\x05') {
    TZone* orderContext = static_cast<TZone*>(reinterpret_cast<void*(__cdecl*)(short)>(
        thunk_GetMapActionContextByTileIndex)(static_cast<short>(tileIndex)));
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
// stash the strided cell record in field7a, and hand it to the slot-0xd dispatcher.
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
  field7a = static_cast<unsigned short>(stridedRecord);
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
  field7a = static_cast<unsigned short>(stridedRecord);
  DispatchQueuedUiCommandAndRelease(event);
}

// FUNCTION: IMPERIALISM 0x005964b0
void TWorldView::HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) {
  (void)nTileIndex;
  (void)nInputFlags;
}

// FUNCTION: IMPERIALISM 0x00596680
void TWorldView::SetMapViewCellCoordinates(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
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

// FUNCTION: IMPERIALISM 0x00596700
void TWorldView::OrphanCallChain_C6_I29_00596700() {}
