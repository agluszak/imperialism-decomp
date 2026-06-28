// TDiplomacyMapView QuickDraw legend rendering slice.

#include "decomp_types.h"
#include "game/TDiplomacyMapView.h"
#include "game/TView.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/quickdraw_globals.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/mfc.h"
#include "game/ui_widget_thunks.h"
#include "game/ClipStateRegion.h"
#include "game/TDiplomacyMgr.h"
#include "game/TStrategicMapViewSystem.h"
#include "game/TControl.h"
#include "game/TGlobalMapState.h"
#include "game/TModuleLibraryCacheTableStateB.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

undefined4 thunk_GetActiveQuickDrawSurfaceContextAndFlags(void);
undefined4 thunk_SetActiveQuickDrawSurfaceContext(void);
undefined4 thunk_GetSurfaceObjectAtContextOffset24(void);
undefined4 thunk_ReturnConstantTrueQuickDrawFlag(void);
undefined4 thunk_NoOpQuickDrawLifecycleHookB(void);
undefined4 thunk_RenderTerrainAndMinorNationLegendLabels(void);
undefined4 SetQuickDrawColorAndSyncGlobals(void);
undefined4 thunk_SetGlobalBlitTransparentColorRaw(void);
undefined4 BlitRectWithOptionalTransparency(void);
undefined4 FrameRegionOnHdcAndReleaseBrushState(void);
undefined4 MapTurnEventCodeToPaletteIndex(void);
undefined4 thunk_SetUiResourceContextTagWord(void);
undefined4 BlitMonochromeMaskBytePatternToSurface(void);
undefined4 thunk_AppendPackedColorDwordToMaskBuffers(void);
undefined4 CombineTwoRegionsIntoDestinationAndUpdateBox(void);
undefined4 UpdatePaletteIndexWithDefaultFallback(void);
undefined4 DrawFrameRectOrUpdateClipRegion(void);
undefined4 SetQuickDrawTextOriginWithContextOffset(void);
undefined4 DrawCenteredGuideLineOnMapDc(void);
undefined4 AppendPointerToGlobalVectorAsStatus(void);
undefined4 thunk_WrapperFor_InvalidateCityDialogRectRegion_At004f6d90(void);
undefined4 RunDiplomacyWaitSheetPopupAndAwaitResponse(void);

namespace {
const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
const unsigned int kAddrDiplomacyTurnStateManager = 0x006A43D0;
const unsigned int kAddrDiplomacyRelationPaletteMap = 0x00696990;
const unsigned int kAddrDiplomacyHitRectInitialized = 0x006A2FBC;
const unsigned int kAddrDiplomacyHitBounds = 0x006A3008;
const unsigned int kAddrResolveDiplomacyActionValue = 0x004F5F70;
} // namespace

IMPLEMENT_DYNCREATE(TDiplomacyMapView, TPicture)

// FUNCTION: IMPERIALISM 0x00430730
DiplomacyMaskBufferRun::~DiplomacyMaskBufferRun() {
  delete[] maskBytesAt00;
}

// FUNCTION: IMPERIALISM 0x004f3b80
TDiplomacyMapView::TDiplomacyMapView() : TPicture() {
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x94) = 0;
  frameRegionSelectorAt98 = 0;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x90) = 0;
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x9c) = 0;
  legendSurfaceModeAt524 = 6;
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0xb8) = 0;
  *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pUiRuntimeContext) + 0x28) = 1;
}

// FUNCTION: IMPERIALISM 0x004f3c70
DiplomacyMaskBufferRun::DiplomacyMaskBufferRun() {
  maskBytesAt00 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004f3c90
// TDiplomacyMapView::`scalar deleting destructor'
TDiplomacyMapView::~TDiplomacyMapView() {}

// FUNCTION: IMPERIALISM 0x004f3d60
void TDiplomacyMapView::NoOpUiLifecycleHook(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x004f3e30
void TDiplomacyMapView::CallVoidSlotA0() {
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0xb8) = 0;
}

// FUNCTION: IMPERIALISM 0x004f3e60
void TDiplomacyMapView::Free() {}

// FUNCTION: IMPERIALISM 0x004f48c0
void TDiplomacyMapView::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x004f5410
void TDiplomacyMapView::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                             int arg4) {
  TPicture::BeginMouseCaptureAndStartRepeatTimer(point, arg2, arg3, arg4);
}

void StrategicMapCallbackRecord::AppendPackedColorDword(int surface, int packedColor) {
  reinterpret_cast<void(__cdecl*)(void*, int, int)>(thunk_AppendPackedColorDwordToMaskBuffers)(
      this, surface, packedColor);
}

// FUNCTION: IMPERIALISM 0x004f5e00
int TDiplomacyMapView::ResolveDiplomacyActionFromClickAndUpdateTarget(CPoint* clickPoint) {
  char* self = reinterpret_cast<char*>(this);
  char initFlags = *reinterpret_cast<char*>(kAddrDiplomacyHitRectInitialized);
  if ((initFlags & 1) == 0) {
    *reinterpret_cast<char*>(kAddrDiplomacyHitRectInitialized) = static_cast<char>(initFlags | 1);
    RECT initRect;
    initRect.left = 0x31;
    initRect.top = 0x2d;
    initRect.right = 0x24d;
    initRect.bottom = 0x159;
    CopyRect(reinterpret_cast<RECT*>(kAddrDiplomacyHitBounds), &initRect);
    reinterpret_cast<int(__cdecl*)(void*)>(AppendPointerToGlobalVectorAsStatus)(
        reinterpret_cast<void*>(kAddrResolveDiplomacyActionValue));
  }

  if (PtInRect(reinterpret_cast<const RECT*>(kAddrDiplomacyHitBounds),
               *reinterpret_cast<const POINT*>(clickPoint)) == 0) {
    return 0;
  }
  if (*reinterpret_cast<int*>(self + 0x94) == 5) {
    return 0;
  }

  CPoint localPoint = this->TransformPointViaSlot138(clickPoint);

  int terrainIndex = 0;
  int* terrainDescriptors = reinterpret_cast<int*>(kAddrTerrainTypeDescriptorTable);
  do {
    if (*terrainDescriptors != 0) {
      char hit = g_pStrategicMapViewSystem->WrapperFor_IsPointInsideHitRegion_At0050d6c0(
          static_cast<short>(terrainIndex));
      if (hit != 0) {
        break;
      }
    }
    terrainDescriptors += 1;
    terrainIndex += 1;
  } while (reinterpret_cast<unsigned int>(terrainDescriptors) < 0x6a436c);

  int actionCode = 0;
  if (terrainIndex < 0x17) {
    actionCode = *reinterpret_cast<int*>(self + 0xbc);
    *reinterpret_cast<short*>(self + 0xc2) = static_cast<short>(terrainIndex);
    if (actionCode != 0xd && terrainIndex == *reinterpret_cast<short*>(self + 0x90)) {
      return 1;
    }
  } else {
    *reinterpret_cast<short*>(self + 0xc2) = static_cast<short>(0xffff);
  }
  return actionCode;
}

// FUNCTION: IMPERIALISM 0x004f5f90
void TDiplomacyMapView::HandleCursorHoverFallback(CPoint* point, int hitArg) {
  (void)point;
  (void)hitArg;
}

// FUNCTION: IMPERIALISM 0x004f5fb0
void TDiplomacyMapView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* clickPoint,
                                                                            int dispatchArg) {
  char* self = reinterpret_cast<char*>(this);
  CPoint localPoint;
  localPoint.x = clickPoint->x;
  localPoint.y = clickPoint->y;

  short cursorTable[16];
  cursorTable[0] = 0x41b;
  cursorTable[1] = 0x41b;
  cursorTable[2] = 0x408;
  cursorTable[3] = 0x407;
  cursorTable[4] = 0x406;
  cursorTable[5] = 0x404;
  cursorTable[6] = 0x405;
  cursorTable[7] = 0x411;
  cursorTable[8] = 0x415;
  cursorTable[9] = 0x409;
  cursorTable[10] = 0x41b;
  cursorTable[11] = 0x40f;
  cursorTable[12] = 0x410;
  cursorTable[13] = 0x3f3;
  cursorTable[14] = 0x419;
  cursorTable[15] = 0x41a;

  void** terrainDescriptors = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
  int hitIndex = 0;
  bool hit = false;
  do {
    if (terrainDescriptors[static_cast<short>(hitIndex)] != 0) {
      char regionHit = g_pStrategicMapViewSystem->WrapperFor_IsPointInsideHitRegion_At0050d6c0(
          static_cast<short>(hitIndex));
      if (regionHit != 0) {
        hit = true;
        break;
      }
    }
    hitIndex += 1;
  } while (static_cast<short>(hitIndex) < 0x17);

  void* hCursor;
  bool applyCursor = false;
  if (hit) {
    int actionCode = ResolveDiplomacyActionFromClickAndUpdateTarget(clickPoint);
    char valid = g_pDiplomacyTurnStateManager->ValidateDiplomacyActionSlot5c(
        *reinterpret_cast<short*>(self + 0x90), *reinterpret_cast<short*>(self + 0xc2), actionCode);

    short cursorId;
    if (valid == 0) {
      cursorId = 0x41b;
    } else {
      cursorId = cursorTable[actionCode];
      if (actionCode == 9 || actionCode == 7 || actionCode == 8) {
        cursorId = static_cast<short>(cursorId + *reinterpret_cast<short*>(self + 0xc0));
      }
    }
    *reinterpret_cast<short*>(self + 0x52a) = cursorId;
    hCursor = *reinterpret_cast<void**>(reinterpret_cast<char*>(g_pUiRuntimeContext) - 0xf8c +
                                        cursorId * 4);
    applyCursor = true;
  } else if (*reinterpret_cast<short*>(self + 0x52a) != 0x41b) {
    *reinterpret_cast<short*>(self + 0x52a) = 0x41b;
    hCursor = *reinterpret_cast<void**>(reinterpret_cast<char*>(g_pUiRuntimeContext) + 0xe0);
    applyCursor = true;
  }

  if (applyCursor) {
    SetCursor(reinterpret_cast<HCURSOR>(hCursor));
  }

  reinterpret_cast<TControl*>(this)->TControl::HandleCursorHoverSelectionByChildHitTestAndFallback(
      clickPoint, dispatchArg);
}

// FUNCTION: IMPERIALISM 0x004f6170
void TDiplomacyMapView::RenderDiplomacyLegendSurfaceAndPresent(const RECT* presentRect) {
  QuickDrawSurfaceGuard surface;
  reinterpret_cast<TView*>(this)->QueryBounds(const_cast<RECT*>(presentRect));

  if (legendSurfaceModeAt524 != 0) {
    int savedTransparentColor = g_pActiveQuickDrawSurfaceContext->transparentBlitColor;
    int savedQuickDrawColor = g_pActiveQuickDrawSurfaceContext->quickDrawColor;

    int* previousSurface = 0;
    int contextFlags = 0;
    reinterpret_cast<void(__cdecl*)(int**, int*)>(thunk_GetActiveQuickDrawSurfaceContextAndFlags)(
        &previousSurface, &contextFlags);
    reinterpret_cast<void(__cdecl*)(int*, int)>(thunk_SetActiveQuickDrawSurfaceContext)(
        reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext), contextFlags);

    if (previousSurface != reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext)) {
      reinterpret_cast<void(__cdecl*)(int*)>(thunk_GetSurfaceObjectAtContextOffset24)(
          reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext));
      reinterpret_cast<void(__cdecl*)()>(thunk_ReturnConstantTrueQuickDrawFlag)();
    }

    reinterpret_cast<TView*>(this)->ApplyRectSlot110(nullptr);

    void** terrainDescriptors = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
    short terrainIndex = 0;
    do {
      if (*terrainDescriptors != 0) {
        this->BlitDiplomacyMapEventPaletteMaskToSurface(terrainIndex, terrainIndex + 0x258);
      }
      terrainIndex = static_cast<short>(terrainIndex + 1);
      terrainDescriptors = terrainDescriptors + 1;
    } while (terrainIndex < 7);

    g_pUiRuntimeContext->ApplyLegendSplitSlot34(0x3f);

    terrainIndex = 7;
    terrainDescriptors = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable) + 7;
    do {
      if (*terrainDescriptors != 0) {
        this->BlitDiplomacyMapEventPaletteMaskToSurface(terrainIndex, 0x2bb);
      }
      terrainIndex = static_cast<short>(terrainIndex + 1);
      terrainDescriptors = terrainDescriptors + 1;
    } while (terrainIndex < 0x17);

    SetQuickDrawFillColor(0);
    reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_RenderTerrainAndMinorNationLegendLabels)(
        this, 0);

    if (previousSurface != reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext)) {
      reinterpret_cast<void(__cdecl*)(int*)>(thunk_GetSurfaceObjectAtContextOffset24)(
          reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext));
      reinterpret_cast<void(__cdecl*)()>(thunk_NoOpQuickDrawLifecycleHookB)();
    }

    reinterpret_cast<void(__cdecl*)(int*, int)>(thunk_SetActiveQuickDrawSurfaceContext)(
        previousSurface, contextFlags);
    reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawColorAndSyncGlobals)(savedQuickDrawColor);
    reinterpret_cast<void(__cdecl*)(int)>(thunk_SetGlobalBlitTransparentColorRaw)(
        savedTransparentColor);
    legendSurfaceModeAt524 = 0;
  }

  if (g_pPrimaryRenderSurfaceContext->GetBlitSurface() !=
      g_pActiveQuickDrawSurfaceContext->GetBlitSurface()) {
    RECT blitRect;
    CopyRect(&blitRect, presentRect);
    BlitQuickDrawSurfaces(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                          g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect, &blitRect,
                          0);
  }

  SetQuickDrawFillColor(0xffffff);
  ClipStateRegionWrapper* frameRegion = g_pStrategicMapViewSystem->GetClipRegionSlotByIndex(
      static_cast<short>(frameRegionSelectorAt98));
  reinterpret_cast<void(__fastcall*)(void*, int, void*)>(FrameRegionOnHdcAndReleaseBrushState)(
      this, 0, frameRegion);
  SetQuickDrawFillColor(0);
}

// FUNCTION: IMPERIALISM 0x004f6440
void TDiplomacyMapView::BuildCombinedTerrainTypeRegionMaskAndDispatch() {
  ClipStateRegionWrapper* region = CreateClipStateRegionWrapperObject();

  short terrainIndex = 0;
  void** terrainDescriptors = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
  do {
    if (*terrainDescriptors != 0) {
      ClipStateRegionWrapper* frameRegion =
          g_pStrategicMapViewSystem->GetClipRegionSlotByIndex(static_cast<short>(terrainIndex));
      CombineTwoRegionsIntoDestinationAndUpdateBox(region, frameRegion, region);
    }
    terrainIndex = static_cast<short>(terrainIndex + 1);
    terrainDescriptors = terrainDescriptors + 1;
  } while (terrainIndex < 0x17);

  this->ForwardMapViewVirtualC4IfPresent(reinterpret_cast<int>(region));
  DestroyClipStateRegionWrapperObject(region);
}

// FUNCTION: IMPERIALISM 0x004f64c0
void TDiplomacyMapView::RebuildDiplomacyLegendPaletteMode4AndBlit(int activeNationSlot,
                                                                  const RECT* presentRect) {
  int* previousSurface = 0;
  int maskState[2] = {0, 0};
  int contextFlags = 0;
  RECT blitRect;
  blitRect.left = presentRect->left;
  blitRect.top = presentRect->top;
  blitRect.right = presentRect->right;
  blitRect.bottom = presentRect->bottom;

  if (legendSurfaceModeAt524 != 4) {
    reinterpret_cast<void(__cdecl*)(int**, int*)>(thunk_GetActiveQuickDrawSurfaceContextAndFlags)(
        &previousSurface, &contextFlags);
    reinterpret_cast<void(__cdecl*)(int*, int)>(thunk_SetActiveQuickDrawSurfaceContext)(
        reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext), contextFlags);
    reinterpret_cast<void(__cdecl*)(int)>(thunk_ReturnConstantTrueQuickDrawFlag)(
        reinterpret_cast<int(__cdecl*)(int*)>(thunk_GetSurfaceObjectAtContextOffset24)(
            reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext)));

    short nationIndex = 0;
    do {
      int eventCode;
      if (nationIndex == static_cast<short>(activeNationSlot)) {
        eventCode = 0x40;
      } else {
        short relationTier =
            g_pDiplomacyTurnStateManager->GetRelationTierSlot70(activeNationSlot, nationIndex);
        eventCode = static_cast<short>(
            reinterpret_cast<unsigned char*>(kAddrDiplomacyRelationPaletteMap)[relationTier]);
      }

      maskState[0] = 0;
      maskState[1] = 0;
      int paletteIndex = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(eventCode);
      reinterpret_cast<void(__cdecl*)()>(thunk_SetUiResourceContextTagWord)();
      maskRuns[nationIndex].BlitMonochromeMaskBytePatternToSurface(
          reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()), paletteIndex,
          maskState, 1);

      int packedColor = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(0x3f);
      packedColorRuns[nationIndex].AppendPackedColorDword(
          reinterpret_cast<unsigned int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()),
          packedColor);

      nationIndex = static_cast<short>(nationIndex + 1);
    } while (nationIndex < 0x17);

    reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_RenderTerrainAndMinorNationLegendLabels)(
        this, 0);
    legendSurfaceModeAt524 = 4;
    reinterpret_cast<void(__cdecl*)(int*)>(thunk_GetSurfaceObjectAtContextOffset24)(
        reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext));
    reinterpret_cast<void(__cdecl*)()>(thunk_NoOpQuickDrawLifecycleHookB)();
    reinterpret_cast<void(__cdecl*)(int*, int)>(thunk_SetActiveQuickDrawSurfaceContext)(
        previousSurface, contextFlags);
  }

  BlitQuickDrawSurfaces(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect, &blitRect,
                        0);
}

// FUNCTION: IMPERIALISM 0x004f66c0
void DiplomacyMaskBufferRun::BlitMonochromeMaskBytePatternToSurface(int surfaceContext,
                                                                    int paletteByte, int* origin,
                                                                    int flipVertical) {
  unsigned char* maskCursor = maskBytesAt00;
  if (maskCursor == 0) {
    return;
  }

  int rowStride = *reinterpret_cast<short*>(surfaceContext + 4);
  unsigned int row = topAt08;
  unsigned char* destCursor;
  int rowAdvance;
  if (static_cast<char>(flipVertical) == 0) {
    destCursor =
        reinterpret_cast<unsigned char*>((origin[1] + row) * rowStride + origin[0] +
                                         *reinterpret_cast<int*>(surfaceContext) + leftAt04);
    rowAdvance = leftAt04 + (rowStride - rightAt0c);
  } else {
    int surfaceHeight = *reinterpret_cast<int*>(
        *reinterpret_cast<int*>(*reinterpret_cast<int*>(surfaceContext + 0x1c) + 0x10) + 8);
    if (surfaceHeight < 1) {
      surfaceHeight = -surfaceHeight;
    }
    destCursor = reinterpret_cast<unsigned char*>(
        (((surfaceHeight - origin[1]) - row) - 1) * rowStride + origin[0] +
        *reinterpret_cast<int*>(surfaceContext) + leftAt04);
    rowAdvance = leftAt04 + (-rowStride - rightAt0c);
  }

  if (static_cast<int>(row) < bottomAt10) {
    do {
      int x = leftAt04;
      unsigned char* rowCursor = destCursor;
      if (x < rightAt0c) {
        do {
          if (*maskCursor == 0) {
            x += 8;
            destCursor = rowCursor + 8;
          } else if (*maskCursor == 0xff) {
            unsigned int fillByte = static_cast<unsigned char>(paletteByte);
            unsigned int packedFill =
                fillByte | (fillByte << 8) | (fillByte << 16) | (fillByte << 24);
            *reinterpret_cast<unsigned int*>(rowCursor) = packedFill;
            *reinterpret_cast<unsigned int*>(rowCursor + 4) = packedFill;
            x += 8;
            destCursor = rowCursor + 8;
          } else {
            int bit = 1;
            destCursor = rowCursor;
            do {
              if ((*maskCursor & static_cast<unsigned char>(bit)) != 0) {
                *destCursor = static_cast<unsigned char>(paletteByte);
              }
              bit = bit * 2;
              x += 1;
              destCursor += 1;
            } while (bit < 0x100);
          }
          maskCursor += 1;
          rowCursor = destCursor;
        } while (x < rightAt0c);
      }
      row += 1;
      destCursor += rowAdvance;
    } while (static_cast<int>(row) < bottomAt10);
  }
}

// FUNCTION: IMPERIALISM 0x004f6820
void TDiplomacyMapView::OrphanLeaf_NoCall_Ins05_004f6820() {}

// FUNCTION: IMPERIALISM 0x004f6840
void TDiplomacyMapView::RebuildDiplomacyLegendPaletteMode1AndBlit(int activeNationSlot,
                                                                  const RECT* presentRect) {
  CString str1;
  CString str2;
  CString str3;
  QuickDrawSurfaceGuard surface;
  frameRegionSelectorAt98 = (short)activeNationSlot;

  int* previousSurface = 0;
  int maskState[2];
  int contextFlags = 0;
  RECT blitRect;
  blitRect.left = presentRect->left;
  blitRect.top = presentRect->top;
  blitRect.right = presentRect->right;
  blitRect.bottom = presentRect->bottom;

  if (legendSurfaceModeAt524 != 1) {
    reinterpret_cast<void(__cdecl*)(int**, int*)>(thunk_GetActiveQuickDrawSurfaceContextAndFlags)(
        &previousSurface, &contextFlags);
    reinterpret_cast<void(__cdecl*)(int*, int)>(thunk_SetActiveQuickDrawSurfaceContext)(
        reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext), contextFlags);
    reinterpret_cast<void(__cdecl*)(int)>(thunk_ReturnConstantTrueQuickDrawFlag)(
        reinterpret_cast<int(__cdecl*)(int*)>(thunk_GetSurfaceObjectAtContextOffset24)(
            reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext)));

    int terrainIndex = 0;
    void** terrainDescriptors = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
    do {
      if (*terrainDescriptors != 0) {
        short eventCode =
            g_pDiplomacyTurnStateManager->GetRelationTypeSlot68(activeNationSlot, terrainIndex);

        maskState[0] = 0;
        maskState[1] = 0;
        int paletteIndex = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(eventCode + 200);
        reinterpret_cast<void(__cdecl*)()>(thunk_SetUiResourceContextTagWord)();
        maskRuns[terrainIndex].BlitMonochromeMaskBytePatternToSurface(
            reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()), paletteIndex,
            maskState, 1);

        int packedColor = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(0x3f);
        packedColorRuns[terrainIndex].AppendPackedColorDword(
            reinterpret_cast<unsigned int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()),
            packedColor);
      }
      terrainIndex++;
      terrainDescriptors++;
    } while (terrainIndex < 0x17);

    reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_RenderTerrainAndMinorNationLegendLabels)(
        this, 0);
    legendSurfaceModeAt524 = 1;
    reinterpret_cast<void(__cdecl*)(int*)>(thunk_GetSurfaceObjectAtContextOffset24)(
        reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext));
    reinterpret_cast<void(__cdecl*)()>(thunk_NoOpQuickDrawLifecycleHookB)();
    reinterpret_cast<void(__cdecl*)(int*, int)>(thunk_SetActiveQuickDrawSurfaceContext)(
        previousSurface, contextFlags);
  }

  BlitQuickDrawSurfaces(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect, &blitRect,
                        0);
  (void)presentRect;
}

// FUNCTION: IMPERIALISM 0x004f6b10
void TDiplomacyMapView::BuildTurnEventMonochromeMaskBuffers(int maskIndex, int eventCode) {
  int maskState[2];
  maskState[0] = 0;
  maskState[1] = 0;
  int paletteIndex = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(eventCode);
  reinterpret_cast<void(__cdecl*)()>(thunk_SetUiResourceContextTagWord)();
  DiplomacyMaskBufferRun* maskRun = &maskRuns[maskIndex];
  maskRun->BlitMonochromeMaskBytePatternToSurface(
      reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()), paletteIndex,
      maskState, 1);

  int packedColor = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(0x3f);
  StrategicMapCallbackRecord* packedRun = &packedColorRuns[maskIndex];
  packedRun->AppendPackedColorDword(
      reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()), packedColor);
}

// FUNCTION: IMPERIALISM 0x004f6bd0
void TDiplomacyMapView::BlitDiplomacyMapEventPaletteMaskToSurface(short maskIndex, int bmpId) {
  TQuickDrawBlitSurface* surfaceCtx = g_pActiveQuickDrawSurfaceContext->GetBlitSurface();
  DiplomacyMaskBufferRun* maskRun = &maskRuns[maskIndex];
  CDib* bmpHandle =
      g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(static_cast<unsigned short>(bmpId));

  unsigned char* maskCursor = maskRun->maskBytesAt00;
  if (maskCursor != 0) {
    int srcRowWidth = bmpHandle->m_pInfoHeader->bmiHeader.biWidth;
    int srcRowAdvance = (((srcRowWidth + 3) & 0xfffffffc) - maskRun->rightAt0c) + maskRun->leftAt04;
    int surfaceHeight = *reinterpret_cast<int*>(
        *reinterpret_cast<int*>(
            *reinterpret_cast<int*>(reinterpret_cast<char*>(surfaceCtx) + 0x1c) + 0x10) +
        8);
    if (surfaceHeight < 1) {
      surfaceHeight = -surfaceHeight;
    }
    int row = maskRun->topAt08;
    int rowStride = *reinterpret_cast<short*>(&surfaceCtx->hdcOrBitmapHandle);
    unsigned char* destCursor = reinterpret_cast<unsigned char*>(
        ((surfaceHeight - row) - 1) * rowStride + surfaceCtx->field00 + maskRun->leftAt04);
    int destRowAdvance = (maskRun->leftAt04 - maskRun->rightAt0c) - rowStride;
    unsigned char* srcCursor = static_cast<unsigned char*>(bmpHandle->m_dibBits);

    if (row < maskRun->bottomAt10) {
      do {
        int x = maskRun->leftAt04;
        if (x < maskRun->rightAt0c) {
          do {
            if (*maskCursor == 0) {
              x += 8;
              destCursor += 8;
              srcCursor += 8;
            } else if (*maskCursor == 0xff) {
              int remaining = 8;
              x += 8;
              do {
                *destCursor = *srcCursor;
                destCursor += 1;
                srcCursor += 1;
                remaining -= 1;
              } while (remaining != 0);
            } else {
              int bit = 1;
              do {
                if ((*maskCursor & static_cast<unsigned char>(bit)) != 0) {
                  *destCursor = *srcCursor;
                }
                bit = bit * 2;
                x += 1;
                destCursor += 1;
                srcCursor += 1;
              } while (bit < 0x100);
            }
            maskCursor += 1;
          } while (x < maskRun->rightAt0c);
        }
        row += 1;
        srcCursor += srcRowAdvance;
        destCursor += destRowAdvance;
      } while (row < maskRun->bottomAt10);
    }
  }

  g_pModuleLibraryCacheState->ReleaseRecordByHandle(bmpHandle);
  int packedColor = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(0x3f);
  StrategicMapCallbackRecord* packedRun = &packedColorRuns[maskIndex];
  packedRun->AppendPackedColorDword(reinterpret_cast<int>(surfaceCtx), packedColor);
}

// FUNCTION: IMPERIALISM 0x004f7040
void TDiplomacyMapView::InvalidateAndRunChildWaitSheet(void* arg1, void* arg2, void* arg3,
                                                       void* arg4) {
  reinterpret_cast<void(__stdcall*)(int)>(
      thunk_WrapperFor_InvalidateCityDialogRectRegion_At004f6d90)(5);
  void* child = *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0xb4);
  reinterpret_cast<void(__fastcall*)(void*, int, void*, void*, void*, void*)>(
      RunDiplomacyWaitSheetPopupAndAwaitResponse)(child, 0, arg1, arg2, arg3, arg4);
}

// FUNCTION: IMPERIALISM 0x004f7080
void TDiplomacyMapView::InvalidateAndForwardTabSwitchToChild(void* arg1, void* arg2, void* arg3) {
  reinterpret_cast<void(__stdcall*)(int)>(
      thunk_WrapperFor_InvalidateCityDialogRectRegion_At004f6d90)(5);
  TControl* child = *reinterpret_cast<TControl**>(reinterpret_cast<char*>(this) + 0xb4);
  child->DeserializeCityProductionQueueCommand(reinterpret_cast<int*>(arg1));
}

// FUNCTION: IMPERIALISM 0x004f70c0
void TDiplomacyMapView::HandleEvent(int commandId, TEventHandler* panelEvent, TEvent* extra) {
  if (commandId == 0x14) {
    int tabIndex = 0;
    int* tagTable = reinterpret_cast<int*>(0x00696978);
    do {
      if (panelEvent->controlTag == *tagTable) {
        break;
      }
      tagTable += 1;
      tabIndex += 1;
    } while (reinterpret_cast<unsigned int>(tagTable) < 0x696990);
    if (tabIndex < 6) {
      reinterpret_cast<void(__stdcall*)(int)>(
          thunk_WrapperFor_InvalidateCityDialogRectRegion_At004f6d90)(tabIndex);
      return;
    }
  } else {
    reinterpret_cast<TControl*>(this)->TControl::HandleEvent(commandId, panelEvent, extra);
  }
}

// FUNCTION: IMPERIALISM 0x004f7130
void TDiplomacyMapView::ForwardParam(int param) {
  char* self = reinterpret_cast<char*>(this);
  if (*reinterpret_cast<int*>(self + 0xb8) == 5) {
    TControl* child = *reinterpret_cast<TControl**>(self + 0xb4);
    child->ForwardParam(param);
    return;
  }
  // Non-virtual call to TEventHandler::ForwardParam's body (orig routes through the
  // ILT thunk at 0x401d61 -> 0x48a380); the qualified call forces static dispatch.
  reinterpret_cast<TEventHandler*>(this)->TEventHandler::ForwardParam(param);
}

// FUNCTION: IMPERIALISM 0x004f71a0
void TDiplomacyMapView::RenderDiplomacyPendingPolicyIconsAndFrames() {
  ResetQuickDrawStrokeState();
  reinterpret_cast<void(__cdecl*)(int)>(UpdatePaletteIndexWithDefaultFallback)(0x10);

  char* self = reinterpret_cast<char*>(this);
  short selectedTier = *reinterpret_cast<short*>(self + 0x528);
  int policyIndex = 0;
  do {
    char* manager = reinterpret_cast<char*>(g_pDiplomacyTurnStateManager);
    short tierValue = *reinterpret_cast<short*>(manager + 0x484 + policyIndex * 2);
    int iconCode = *reinterpret_cast<signed char*>(manager + 0x304 + policyIndex);
    if (*reinterpret_cast<char*>(self + 0x52c + policyIndex) != 0 && iconCode != -1 &&
        tierValue <= selectedTier) {
      RECT* iconRect = reinterpret_cast<RECT*>(self + 0x6ac + policyIndex * 0x10);
      short iconX = g_pGlobalMapState->QueryIconStripXSlot110(iconCode);

      RECT srcRect;
      srcRect.left = iconX;
      srcRect.right = iconX + 9;
      srcRect.top = 0;
      srcRect.bottom = 6;

      RECT destRect;
      destRect.left = iconRect->left;
      destRect.top = iconRect->top;
      destRect.right = iconRect->right;
      destRect.bottom = iconRect->bottom;

      int surfaceObject = g_pActiveQuickDrawSurfaceContext->flipDescriptor;
      if (surfaceObject != 0) {
        int surfaceHeight =
            *reinterpret_cast<int*>(*reinterpret_cast<int*>(surfaceObject + 0x10) + 8);
        if (surfaceHeight < 1) {
          surfaceHeight = -surfaceHeight;
        }
        OffsetRect(&destRect, 0, (surfaceHeight - destRect.top) - destRect.bottom);
      }

      int strategicMapSurface =
          *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x6b8);
      BlitQuickDrawSurfaces(
          reinterpret_cast<TQuickDrawSurfaceContext*>(strategicMapSurface)->GetBlitSurface(),
          g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect, &destRect, 0x24);

      destRect.left = iconRect->left - 1;
      destRect.top = iconRect->top - 1;
      destRect.right = iconRect->right + 1;
      destRect.bottom = iconRect->bottom + 1;
      if (tierValue == selectedTier) {
        g_pUiRuntimeContext->ApplyLegendSplitSlot34(6);
      } else {
        SetQuickDrawFillColor(0xffffff);
      }
      reinterpret_cast<void(__cdecl*)(RECT*)>(DrawFrameRectOrUpdateClipRegion)(&destRect);
      SetQuickDrawFillColor(0);
      reinterpret_cast<void(__cdecl*)(short, short)>(SetQuickDrawTextOriginWithContextOffset)(
          static_cast<short>(destRect.right), static_cast<short>(destRect.top));
      reinterpret_cast<void(__cdecl*)(int, int)>(DrawCenteredGuideLineOnMapDc)(destRect.right,
                                                                               destRect.bottom);
      reinterpret_cast<void(__cdecl*)(int, int)>(DrawCenteredGuideLineOnMapDc)(destRect.left,
                                                                               destRect.bottom);
    }
    policyIndex += 1;
  } while (policyIndex < 0x180);

  reinterpret_cast<void(__cdecl*)(int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
}
