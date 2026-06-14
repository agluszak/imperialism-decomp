// TDiplomacyMapView QuickDraw legend rendering slice.

#include "decomp_types.h"
#include "game/TView.h"
#include "game/Point32.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/quickdraw_globals.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/win_rect.h"
#include "game/ui_widget_thunks.h"
#include <new>
#include "game/generated/vcall_facades.h"
#include "game/TControl.h"
#include "game/TDiplomacyTurnStateManager.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" int __stdcall PtInRect(const RECT* rect, Point32 point);
extern "C" void* __stdcall SetCursor(void* hCursor);

#define DUMMY_VIRTUAL(n) virtual void Dummy##n() = 0;

struct TDiplomacyMapViewLayout {
  DUMMY_VIRTUAL(0)
  DUMMY_VIRTUAL(1)
  DUMMY_VIRTUAL(2) DUMMY_VIRTUAL(3) DUMMY_VIRTUAL(4) DUMMY_VIRTUAL(5) DUMMY_VIRTUAL(
      6) DUMMY_VIRTUAL(7) DUMMY_VIRTUAL(8) DUMMY_VIRTUAL(9) DUMMY_VIRTUAL(10) DUMMY_VIRTUAL(11)
      DUMMY_VIRTUAL(12) DUMMY_VIRTUAL(13) DUMMY_VIRTUAL(14) DUMMY_VIRTUAL(15) DUMMY_VIRTUAL(16)
          DUMMY_VIRTUAL(17) DUMMY_VIRTUAL(18) DUMMY_VIRTUAL(19) DUMMY_VIRTUAL(20) DUMMY_VIRTUAL(21)
              DUMMY_VIRTUAL(22) DUMMY_VIRTUAL(23) DUMMY_VIRTUAL(24) DUMMY_VIRTUAL(25)
                  DUMMY_VIRTUAL(26) DUMMY_VIRTUAL(27) DUMMY_VIRTUAL(28) DUMMY_VIRTUAL(29)
                      DUMMY_VIRTUAL(30) DUMMY_VIRTUAL(31) DUMMY_VIRTUAL(32) DUMMY_VIRTUAL(33)
                          DUMMY_VIRTUAL(34) DUMMY_VIRTUAL(35) DUMMY_VIRTUAL(36) DUMMY_VIRTUAL(37)
                              DUMMY_VIRTUAL(38) DUMMY_VIRTUAL(39) DUMMY_VIRTUAL(40)
                                  DUMMY_VIRTUAL(41) DUMMY_VIRTUAL(42) DUMMY_VIRTUAL(43)
                                      DUMMY_VIRTUAL(44) DUMMY_VIRTUAL(45) DUMMY_VIRTUAL(46)
                                          DUMMY_VIRTUAL(47)
                                              DUMMY_VIRTUAL(48) virtual void ApplyClipRegionSlotC4(
                                                  int region) = 0; // slot 49 (0xC4)

  char pad_04[0x94];
  short frameRegionSelectorAt98;
  char pad_9a[0x48a];
  int legendSurfaceModeAt524;

  void RenderDiplomacyLegendSurfaceAndPresent(const RECT* presentRect);
  void RebuildDiplomacyLegendPaletteMode4AndBlit(int activeNationSlot, const RECT* presentRect);
  void RebuildDiplomacyLegendPaletteMode1AndBlit(int activeNationSlot, const RECT* presentRect);
  void BlitDiplomacyMapEventPaletteMaskToSurface(short maskIndex, int bmpId);
  void BuildTurnEventMonochromeMaskBuffers(int maskIndex, int eventCode);
  void BuildCombinedTerrainTypeRegionMaskAndDispatch();
  void RenderDiplomacyPendingPolicyIconsAndFrames();
  int ResolveDiplomacyActionFromClickAndUpdateTarget(Point32* clickPoint);
  void UpdateDiplomacyMapHoverCursorFromActionSelection(Point32* clickPoint, void* dispatchArg);
  void ForwardCityDialogParamToActiveChildOrBase(void* param);
  void InvalidateAndForwardTabSwitchToChild(void* arg1, void* arg2, void* arg3);
  void InvalidateAndRunChildWaitSheet(void* arg1, void* arg2, void* arg3, void* arg4);
};

undefined4 thunk_GetActiveQuickDrawSurfaceContextAndFlags(void);
undefined4 thunk_SetActiveQuickDrawSurfaceContext(void);
undefined4 thunk_GetSurfaceObjectAtContextOffset24(void);
undefined4 thunk_ReturnConstantTrueQuickDrawFlag(void);
undefined4 thunk_NoOpQuickDrawLifecycleHookB(void);
undefined4 thunk_RenderHintHelperWithCtrlModifierOverlay(void);
undefined4 thunk_RenderTerrainAndMinorNationLegendLabels(void);
undefined4 SetQuickDrawColorAndSyncGlobals(void);
undefined4 thunk_SetGlobalBlitTransparentColorRaw(void);
undefined4 BlitRectWithOptionalTransparency(void);
undefined4 FrameRegionOnHdcAndReleaseBrushState(void);
undefined4 MapTurnEventCodeToPaletteIndex(void);
undefined4 thunk_SetUiResourceContextTagWord(void);
undefined4 BlitMonochromeMaskBytePatternToSurface(void);
undefined4 thunk_AppendPackedColorDwordToMaskBuffers(void);
undefined4 thunk_LoadBmpResourceByIdCached(void);
undefined4 thunk_ReleaseHashIndexedRecordByHandle(void);
undefined4 CreateClipStateRegionWrapperObject(void);
undefined4 CombineTwoRegionsIntoDestinationAndUpdateBox(void);
undefined4 DestroyClipStateRegionWrapperObject(int* wrapperObject);
undefined4 UpdatePaletteIndexWithDefaultFallback(void);
undefined4 DrawFrameRectOrUpdateClipRegion(void);
undefined4 SetQuickDrawTextOriginWithContextOffset(void);
undefined4 DrawCenteredGuideLineOnMapDc(void);
undefined4 AppendPointerToGlobalVectorAsStatus(void);
undefined4 thunk_WrapperFor_InvalidateCityDialogRectRegion_At004f6d90(void);
undefined4 thunk_ForwardCityDialogParamToChildSlot48(void);
undefined4 RunDiplomacyWaitSheetPopupAndAwaitResponse(void);

namespace {
const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
const unsigned int kAddrStrategicMapViewSystem = 0x006A21A8;
const unsigned int kAddrDiplomacyTurnStateManager = 0x006A43D0;
const unsigned int kAddrDiplomacyRelationPaletteMap = 0x00696990;
const unsigned int kAddrGlobalMapState = 0x006A43D4;
const unsigned int kAddrDiplomacyHitRectInitialized = 0x006A2FBC;
const unsigned int kAddrDiplomacyHitBounds = 0x006A3008;
const unsigned int kAddrResolveDiplomacyActionValue = 0x004F5F70;
} // namespace

struct DiplomacyMaskBufferRun {
  unsigned char* maskBytesAt00;
  int leftAt04;
  int topAt08;
  int rightAt0c;
  int bottomAt10;

  void BlitMonochromeMaskBytePatternToSurface(int surfaceContext, int paletteByte, int* origin,
                                              int flipVertical);
};

// Packed-color run subobject at `this+0x2078 + index*0x30` (0x30-byte stride).
struct DiplomacyPackedColorRun {
  void AppendPackedColorDword(int surface, int packedColor);
};

// Cached BMP/library record manager at global `g_pModuleLibraryCacheState` (0x6a134c).
// Records are loaded by id and released by handle through the hash-indexed cache.
struct ModuleLibraryCacheState {
  int LoadBmpResourceById(int bmpId);
  void ReleaseRecordByHandle(int handle);
};

// GLOBAL: IMPERIALISM 0x6a134c
extern "C" ModuleLibraryCacheState* g_pModuleLibraryCacheState = 0;

int ModuleLibraryCacheState::LoadBmpResourceById(int bmpId) {
  return reinterpret_cast<int(__cdecl*)(void*, int)>(thunk_LoadBmpResourceByIdCached)(this, bmpId);
}

void ModuleLibraryCacheState::ReleaseRecordByHandle(int handle) {
  reinterpret_cast<void(__cdecl*)(void*, int)>(thunk_ReleaseHashIndexedRecordByHandle)(this,
                                                                                       handle);
}

void DiplomacyPackedColorRun::AppendPackedColorDword(int surface, int packedColor) {
  reinterpret_cast<void(__cdecl*)(void*, int, int)>(thunk_AppendPackedColorDwordToMaskBuffers)(
      this, surface, packedColor);
}

// FUNCTION: IMPERIALISM 0x004f6170
void TDiplomacyMapViewLayout::RenderDiplomacyLegendSurfaceAndPresent(const RECT* presentRect) {
  QuickDrawSurfaceGuard surface;
  reinterpret_cast<TView*>(this)->QueryBounds(
      reinterpret_cast<int*>(const_cast<RECT*>(presentRect)));

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

    reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_RenderHintHelperWithCtrlModifierOverlay)(
        this, 0);

    void** terrainDescriptors = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
    short terrainIndex = 0;
    do {
      if (*terrainDescriptors != 0) {
        VCall_DiplomacyLegend_DrawTerrainSlot1E0(this, terrainIndex, terrainIndex + 0x258);
      }
      terrainIndex = static_cast<short>(terrainIndex + 1);
      terrainDescriptors = terrainDescriptors + 1;
    } while (terrainIndex < 7);

    g_pUiRuntimeContext->ApplyLegendSplitSlot34(0x3f);

    terrainIndex = 7;
    terrainDescriptors = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable) + 7;
    do {
      if (*terrainDescriptors != 0) {
        VCall_DiplomacyLegend_DrawTerrainSlot1E0(this, terrainIndex, 0x2bb);
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
                          g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect,
                          &blitRect, 0);
  }

  SetQuickDrawFillColor(0xffffff);
  void* frameRegion = VCall_StrategicMap_GetFrameRegionSlot98(
      *reinterpret_cast<void**>(kAddrStrategicMapViewSystem), frameRegionSelectorAt98);
  reinterpret_cast<void(__fastcall*)(void*, int, void*)>(FrameRegionOnHdcAndReleaseBrushState)(
      this, 0, frameRegion);
  SetQuickDrawFillColor(0);
}

// FUNCTION: IMPERIALISM 0x004f64c0
void TDiplomacyMapViewLayout::RebuildDiplomacyLegendPaletteMode4AndBlit(int activeNationSlot,
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

    char* maskCursor = reinterpret_cast<char*>(this) + 0x1eac;
    char* packedColorCursor = reinterpret_cast<char*>(this) + 0x2078;
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
      reinterpret_cast<DiplomacyMaskBufferRun*>(maskCursor)
          ->BlitMonochromeMaskBytePatternToSurface(reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()),
                                                   paletteIndex, maskState, 1);

      int packedColor = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(0x3f);
      reinterpret_cast<void(__cdecl*)(void*, unsigned int, int)>(
          thunk_AppendPackedColorDwordToMaskBuffers)(
          packedColorCursor,
          reinterpret_cast<unsigned int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()),
          packedColor);

      nationIndex = static_cast<short>(nationIndex + 1);
      maskCursor += 0x14;
      packedColorCursor += 0x30;
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
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect,
                        &blitRect, 0);
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

// FUNCTION: IMPERIALISM 0x004f6840
void TDiplomacyMapViewLayout::RebuildDiplomacyLegendPaletteMode1AndBlit(int activeNationSlot,
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

    char* maskCursor = reinterpret_cast<char*>(this) + 0x1eac;
    char* packedColorCursor = reinterpret_cast<char*>(this) + 0x2078;
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
        reinterpret_cast<DiplomacyMaskBufferRun*>(maskCursor)
            ->BlitMonochromeMaskBytePatternToSurface(reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()),
                                                     paletteIndex, maskState, 1);

        int packedColor = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(0x3f);
        reinterpret_cast<void(__cdecl*)(void*, unsigned int, int)>(
            thunk_AppendPackedColorDwordToMaskBuffers)(
            packedColorCursor,
            reinterpret_cast<unsigned int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()),
            packedColor);
      }
      terrainIndex++;
      terrainDescriptors++;
      maskCursor += 0x14;
      packedColorCursor += 0x30;
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
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect,
                        &blitRect, 0);
  (void)presentRect;
}

// FUNCTION: IMPERIALISM 0x004f6bd0
void TDiplomacyMapViewLayout::BlitDiplomacyMapEventPaletteMaskToSurface(short maskIndex,
                                                                        int bmpId) {
  TQuickDrawBlitSurface* surfaceCtx = g_pActiveQuickDrawSurfaceContext->GetBlitSurface();
  DiplomacyMaskBufferRun* maskRun = reinterpret_cast<DiplomacyMaskBufferRun*>(
      reinterpret_cast<char*>(this) + 0x1eac + maskIndex * 0x14);
  int bmpHandle = g_pModuleLibraryCacheState->LoadBmpResourceById(bmpId);

  unsigned char* maskCursor = maskRun->maskBytesAt00;
  if (maskCursor != 0) {
    int srcRowWidth = *reinterpret_cast<int*>(*reinterpret_cast<int*>(bmpHandle + 0x10) + 4);
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
    unsigned char* srcCursor = *reinterpret_cast<unsigned char**>(bmpHandle + 0xc);

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
  DiplomacyPackedColorRun* packedRun = reinterpret_cast<DiplomacyPackedColorRun*>(
      reinterpret_cast<char*>(this) + 0x2078 + maskIndex * 0x30);
  packedRun->AppendPackedColorDword(reinterpret_cast<int>(surfaceCtx), packedColor);
}

// FUNCTION: IMPERIALISM 0x004f7040
void TDiplomacyMapViewLayout::InvalidateAndRunChildWaitSheet(void* arg1, void* arg2, void* arg3,
                                                             void* arg4) {
  reinterpret_cast<void(__stdcall*)(int)>(
      thunk_WrapperFor_InvalidateCityDialogRectRegion_At004f6d90)(5);
  void* child = *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0xb4);
  reinterpret_cast<void(__fastcall*)(void*, int, void*, void*, void*, void*)>(
      RunDiplomacyWaitSheetPopupAndAwaitResponse)(child, 0, arg1, arg2, arg3, arg4);
}

// FUNCTION: IMPERIALISM 0x004f7080
void TDiplomacyMapViewLayout::InvalidateAndForwardTabSwitchToChild(void* arg1, void* arg2,
                                                                   void* arg3) {
  reinterpret_cast<void(__stdcall*)(int)>(
      thunk_WrapperFor_InvalidateCityDialogRectRegion_At004f6d90)(5);
  TControl* child = *reinterpret_cast<TControl**>(reinterpret_cast<char*>(this) + 0xb4);
  child->SwitchTab(reinterpret_cast<int*>(arg1));
}

// FUNCTION: IMPERIALISM 0x004f7130
void TDiplomacyMapViewLayout::ForwardCityDialogParamToActiveChildOrBase(void* param) {
  char* self = reinterpret_cast<char*>(this);
  if (*reinterpret_cast<int*>(self + 0xb8) == 5) {
    TControl* child = *reinterpret_cast<TControl**>(self + 0xb4);
    child->ForwardParam(reinterpret_cast<int>(param));
    return;
  }
  reinterpret_cast<void(__fastcall*)(void*, int, void*)>(thunk_ForwardCityDialogParamToChildSlot48)(
      this, 0, param);
}

// FUNCTION: IMPERIALISM 0x004f70c0
void __stdcall HandleDiplomacyMapControlTagToggleOrForward(int commandId, int panelEvent,
                                                           void* extra) {
  if (commandId == 0x14) {
    int tabIndex = 0;
    int* tagTable = reinterpret_cast<int*>(0x00696978);
    do {
      if (*reinterpret_cast<int*>(panelEvent + 0x1c) == *tagTable) {
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
    reinterpret_cast<void(__stdcall*)(int, int, void*)>(
        thunk_HandleCityDialogToggleCommandOrForward)(commandId, panelEvent, extra);
  }
}

// FUNCTION: IMPERIALISM 0x004f5fb0
void TDiplomacyMapViewLayout::UpdateDiplomacyMapHoverCursorFromActionSelection(Point32* clickPoint,
                                                                               void* dispatchArg) {
  char* self = reinterpret_cast<char*>(this);
  Point32 localPoint;
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
      char regionHit = VCall_StrategicMap_HitTestPointSlot90(
          *reinterpret_cast<void**>(kAddrStrategicMapViewSystem),
          reinterpret_cast<int>(&localPoint), hitIndex);
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
    char valid = VCall_DiplomacyTurnState_ValidateActionSlot5C(
        g_pDiplomacyTurnStateManager, *reinterpret_cast<short*>(self + 0x90),
        *reinterpret_cast<short*>(self + 0xc2), actionCode);

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
    SetCursor(hCursor);
  }

  reinterpret_cast<void(__fastcall*)(void*, int, void*, void*)>(
      thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(this, 0, clickPoint, dispatchArg);
}

// FUNCTION: IMPERIALISM 0x004f5e00
int TDiplomacyMapViewLayout::ResolveDiplomacyActionFromClickAndUpdateTarget(Point32* clickPoint) {
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

  if (PtInRect(reinterpret_cast<RECT*>(kAddrDiplomacyHitBounds), *clickPoint) == 0) {
    return 0;
  }
  if (*reinterpret_cast<int*>(self + 0x94) == 5) {
    return 0;
  }

  Point32 localPoint;
  VCall_DiplomacyMapView_TransformPointToLocalSlot148(this, reinterpret_cast<int>(&localPoint),
                                                      reinterpret_cast<int>(clickPoint));

  int terrainIndex = 0;
  int* terrainDescriptors = reinterpret_cast<int*>(kAddrTerrainTypeDescriptorTable);
  do {
    if (*terrainDescriptors != 0) {
      char hit = VCall_StrategicMap_HitTestPointSlot90(
          *reinterpret_cast<void**>(kAddrStrategicMapViewSystem),
          reinterpret_cast<int>(&localPoint), terrainIndex);
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

// FUNCTION: IMPERIALISM 0x004f71a0
void TDiplomacyMapViewLayout::RenderDiplomacyPendingPolicyIconsAndFrames() {
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
      short iconX = VCall_GlobalMapState_QueryIconStripXSlot110(
          *reinterpret_cast<void**>(kAddrGlobalMapState), iconCode);

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
          *reinterpret_cast<int*>(*reinterpret_cast<int*>(kAddrStrategicMapViewSystem) + 0x6b8);
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

// FUNCTION: IMPERIALISM 0x004f6440
void TDiplomacyMapViewLayout::BuildCombinedTerrainTypeRegionMaskAndDispatch() {
  void* region = reinterpret_cast<void*(__cdecl*)()>(CreateClipStateRegionWrapperObject)();

  short terrainIndex = 0;
  void** terrainDescriptors = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
  do {
    if (*terrainDescriptors != 0) {
      void* frameRegion = VCall_StrategicMap_GetFrameRegionSlot98(
          *reinterpret_cast<void**>(kAddrStrategicMapViewSystem), terrainIndex);
      reinterpret_cast<void(__cdecl*)(void*, void*, void*)>(
          CombineTwoRegionsIntoDestinationAndUpdateBox)(region, frameRegion, region);
    }
    terrainIndex = static_cast<short>(terrainIndex + 1);
    terrainDescriptors = terrainDescriptors + 1;
  } while (terrainIndex < 0x17);

  this->ApplyClipRegionSlotC4(reinterpret_cast<int>(region));
  reinterpret_cast<void(__cdecl*)(void*)>(DestroyClipStateRegionWrapperObject)(region);
}

// FUNCTION: IMPERIALISM 0x004f6b10
void TDiplomacyMapViewLayout::BuildTurnEventMonochromeMaskBuffers(int maskIndex, int eventCode) {
  int maskState[2];
  maskState[0] = 0;
  maskState[1] = 0;
  int paletteIndex = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(eventCode);
  reinterpret_cast<void(__cdecl*)()>(thunk_SetUiResourceContextTagWord)();
  DiplomacyMaskBufferRun* maskRun = reinterpret_cast<DiplomacyMaskBufferRun*>(
      reinterpret_cast<char*>(this) + 0x1eac + maskIndex * 0x14);
  maskRun->BlitMonochromeMaskBytePatternToSurface(reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()),
                                                  paletteIndex, maskState, 1);

  int packedColor = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(0x3f);
  DiplomacyPackedColorRun* packedRun = reinterpret_cast<DiplomacyPackedColorRun*>(
      reinterpret_cast<char*>(this) + 0x2078 + maskIndex * 0x30);
  packedRun->AppendPackedColorDword(
      reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()), packedColor);
}

// FUNCTION: IMPERIALISM 0x00409205
int UiRuntimeContext::MapTurnEventCodeToPaletteIndex(int eventCode) {
  return reinterpret_cast<int(__cdecl*)(int)>(::MapTurnEventCodeToPaletteIndex)(eventCode);
}
