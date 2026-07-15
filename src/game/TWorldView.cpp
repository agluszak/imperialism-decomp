#include "game/TWorldView.h"

#include "game/TApplication.h"
#include "game/TArmyMgr.h"
#include "game/TCivMgr.h"
#include "game/TCivUnit.h"
#include "game/mfc.h"
#include "game/CTemporaryRegion.h"
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

namespace {

#define kAddrTEventClassVtable 0x00649770
#define kAddrActiveMapTileIndexStorage 0x006a45ec

struct TOverlayDispatchEventBlock {
  void* vtable;
  int commandA;
  int commandB;
  TWorldView* view;
  TWorldView* viewCopy;
};

void DispatchOverlayEvent78Common(TWorldView* self, int stridedRecord) {
  TOverlayDispatchEventBlock* eventBlock = new TOverlayDispatchEventBlock();
  if (eventBlock == 0) {
    return;
  }
  eventBlock->commandA = 0;
  eventBlock->commandB = 0;
  eventBlock->view = 0;
  eventBlock->viewCopy = 0;
  eventBlock->vtable = reinterpret_cast<void*>(kAddrTEventClassVtable);
  eventBlock->commandB = 0x78;
  eventBlock->commandA = 0x78;
  eventBlock->view = self;
  eventBlock->viewCopy = self;
  *reinterpret_cast<unsigned short*>(reinterpret_cast<char*>(self) + 0x7a) =
      static_cast<unsigned short>(stridedRecord);
  self->DispatchEvent(reinterpret_cast<int>(eventBlock),
                      reinterpret_cast<TEventHandler*>(eventBlock), 0);
}

} // namespace

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
  int childVtable = *reinterpret_cast<int*>(mapUberPicture);
  typedef void(__fastcall * ChildSlot128Fn)(void* self, int unusedEdx, long* bottomOut);
  reinterpret_cast<ChildSlot128Fn>(*reinterpret_cast<int*>(childVtable + 0x128))(mapUberPicture, 0,
                                                                                 &clipRect.bottom);

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
  TOverlayDispatchEventBlock* eventBlock = new TOverlayDispatchEventBlock();
  TOverlayDispatchEventBlock* eventPtr = 0;
  if (eventBlock != 0) {
    eventBlock->commandA = 0;
    eventBlock->commandB = 0;
    eventBlock->view = 0;
    eventBlock->viewCopy = 0;
    eventBlock->vtable = reinterpret_cast<void*>(kAddrTEventClassVtable);
    eventPtr = eventBlock;
  }

  short tileIndex = static_cast<short>(arg1);
  char* terrainTable = reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable);
  if (terrainTable[tileIndex * 0x24] == '\x05') {
    TZone* orderContext = static_cast<TZone*>(
        reinterpret_cast<void*(__cdecl*)(short)>(thunk_GetMapActionContextByTileIndex)(tileIndex));
    // ownerContext is really a TMapUberPicture* (see the class-attribution note on
    // TMapUberPicture::SetMapInteractionMode); SetActiveMapOrderEntry already reproduces
    // this exact invalidate-old/set/invalidate-new/refresh sequence.
    static_cast<TMapUberPicture*>(ownerContext)->SetActiveMapOrderEntry(orderContext);
  }

  *reinterpret_cast<int*>(kAddrActiveMapTileIndexStorage + 0x28) = tileIndex;
  if (eventPtr == 0) {
    return;
  }
  eventPtr->commandB = 0x79;
  eventPtr->commandA = 0x79;
  eventPtr->view = this;
  eventPtr->viewCopy = this;
  DispatchEvent(reinterpret_cast<int>(eventPtr), reinterpret_cast<TEventHandler*>(eventPtr), 0);
}

// FUNCTION: IMPERIALISM 0x005963d0
void TWorldView::DispatchOverlayEvent78FromStridedRecord(int stridedRecord, int dispatchContext) {
  (void)dispatchContext;
  DispatchOverlayEvent78Common(this, stridedRecord);
}

// FUNCTION: IMPERIALISM 0x00596440
void TWorldView::DispatchOverlayEvent78RootHighFromStridedRecord(int stridedRecord,
                                                                 int dispatchContext) {
  (void)dispatchContext;
  DispatchOverlayEvent78Common(this, stridedRecord);
}

// FUNCTION: IMPERIALISM 0x005964b0
void TWorldView::HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) {
  (void)nTileIndex;
  (void)nInputFlags;
}

// FUNCTION: IMPERIALISM 0x00596680
void TWorldView::OrphanRetStub_00596680(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

// FUNCTION: IMPERIALISM 0x005966a0
void TWorldView::OrphanRetStub_005966a0(int arg1) {
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
