// TDiplomacyMapView QuickDraw legend rendering slice.

#include "decomp_types.h"
#include "game/generated/vcall_facades.h"
#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

struct TDiplomacyMapViewLayout {
  void* vftable;
  char pad_04[0x94];
  short frameRegionSelectorAt98;
  char pad_9a[0x48a];
  int legendSurfaceModeAt524;

  void RenderDiplomacyLegendSurfaceAndPresent(const RECT* presentRect);
  void RebuildDiplomacyLegendPaletteMode4AndBlit(int activeNationSlot, const RECT* presentRect);
  void RebuildDiplomacyLegendPaletteMode1AndBlit(int activeNationSlot, const RECT* presentRect);
  void BlitDiplomacyMapEventPaletteMaskToSurface(short maskIndex, int bmpId);
  void BuildTurnEventMonochromeMaskBuffers(int maskIndex, int eventCode);
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

extern int g_pPrimaryRenderSurfaceContext;
extern int g_pActiveQuickDrawSurfaceContext;

namespace {
const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
const unsigned int kAddrStrategicMapViewSystem = 0x006A21A8;
const unsigned int kAddrDiplomacyTurnStateManager = 0x006A43D0;
const unsigned int kAddrDiplomacyRelationPaletteMap = 0x00696990;
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
  VCall_QuickDrawTarget_QueryBoundsSlot12C(this,
                                           reinterpret_cast<int*>(const_cast<RECT*>(presentRect)));

  if (legendSurfaceModeAt524 != 0) {
    int savedTransparentColor = *reinterpret_cast<int*>(g_pActiveQuickDrawSurfaceContext + 0x2c);
    int savedQuickDrawColor = *reinterpret_cast<int*>(g_pActiveQuickDrawSurfaceContext + 0x28);

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

    VCall_UiRuntime_ApplyLegendSplitSlot34(g_pUiRuntimeContext, 0x3f);

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

  if (g_pPrimaryRenderSurfaceContext + 4 != g_pActiveQuickDrawSurfaceContext + 4) {
    RECT blitRect;
    CopyRect(&blitRect, presentRect);
    reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, int, void*)>(
        BlitRectWithOptionalTransparency)(
        reinterpret_cast<void*>(g_pPrimaryRenderSurfaceContext + 4),
        reinterpret_cast<void*>(g_pActiveQuickDrawSurfaceContext + 4), &blitRect, &blitRect, 0, 0);
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
        short relationTier = VCall_Diplomacy_GetRelationTierSlot70(
            *reinterpret_cast<void**>(kAddrDiplomacyTurnStateManager), activeNationSlot,
            nationIndex);
        eventCode = static_cast<short>(
            reinterpret_cast<unsigned char*>(kAddrDiplomacyRelationPaletteMap)[relationTier]);
      }

      maskState[0] = 0;
      maskState[1] = 0;
      int paletteIndex = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(eventCode);
      reinterpret_cast<void(__cdecl*)()>(thunk_SetUiResourceContextTagWord)();
      reinterpret_cast<DiplomacyMaskBufferRun*>(maskCursor)
          ->BlitMonochromeMaskBytePatternToSurface(g_pActiveQuickDrawSurfaceContext + 4,
                                                   paletteIndex, maskState, 1);

      int packedColor = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(0x3f);
      reinterpret_cast<void(__cdecl*)(void*, unsigned int, int)>(
          thunk_AppendPackedColorDwordToMaskBuffers)(
          packedColorCursor, *reinterpret_cast<unsigned int*>(g_pActiveQuickDrawSurfaceContext + 4),
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

  reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, int, void*)>(
      BlitRectWithOptionalTransparency)(
      reinterpret_cast<void*>(g_pPrimaryRenderSurfaceContext + 4),
      reinterpret_cast<void*>(g_pActiveQuickDrawSurfaceContext + 4), &blitRect, &blitRect, 0, 0);
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
  StringShared str1;
  StringShared str2;
  StringShared str3;
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
        short eventCode = VCall_Diplomacy_GetRelationTypeSlot68(
            *reinterpret_cast<void**>(kAddrDiplomacyTurnStateManager), activeNationSlot,
            terrainIndex);

        maskState[0] = 0;
        maskState[1] = 0;
        int paletteIndex = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(eventCode + 200);
        reinterpret_cast<void(__cdecl*)()>(thunk_SetUiResourceContextTagWord)();
        reinterpret_cast<DiplomacyMaskBufferRun*>(maskCursor)
            ->BlitMonochromeMaskBytePatternToSurface(g_pActiveQuickDrawSurfaceContext + 4,
                                                     paletteIndex, maskState, 1);

        int packedColor = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(0x3f);
        reinterpret_cast<void(__cdecl*)(void*, unsigned int, int)>(
            thunk_AppendPackedColorDwordToMaskBuffers)(
            packedColorCursor,
            *reinterpret_cast<unsigned int*>(g_pActiveQuickDrawSurfaceContext + 4), packedColor);
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

  reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, int, void*)>(
      BlitRectWithOptionalTransparency)(
      reinterpret_cast<void*>(g_pPrimaryRenderSurfaceContext + 4),
      reinterpret_cast<void*>(g_pActiveQuickDrawSurfaceContext + 4), &blitRect, &blitRect, 0, 0);
  (void)presentRect;
}

// FUNCTION: IMPERIALISM 0x004f6bd0
void TDiplomacyMapViewLayout::BlitDiplomacyMapEventPaletteMaskToSurface(short maskIndex,
                                                                        int bmpId) {
  int* surfaceCtx = reinterpret_cast<int*>(g_pActiveQuickDrawSurfaceContext + 4);
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
    int rowStride = *reinterpret_cast<short*>(reinterpret_cast<char*>(surfaceCtx) + 4);
    unsigned char* destCursor = reinterpret_cast<unsigned char*>(
        ((surfaceHeight - row) - 1) * rowStride + *surfaceCtx + maskRun->leftAt04);
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
  packedRun->AppendPackedColorDword(*surfaceCtx, packedColor);
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
  maskRun->BlitMonochromeMaskBytePatternToSurface(g_pActiveQuickDrawSurfaceContext + 4,
                                                  paletteIndex, maskState, 1);

  int packedColor = g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(0x3f);
  DiplomacyPackedColorRun* packedRun = reinterpret_cast<DiplomacyPackedColorRun*>(
      reinterpret_cast<char*>(this) + 0x2078 + maskIndex * 0x30);
  packedRun->AppendPackedColorDword(*reinterpret_cast<int*>(g_pActiveQuickDrawSurfaceContext + 4),
                                    packedColor);
}

// FUNCTION: IMPERIALISM 0x00409205
int UiRuntimeContext::MapTurnEventCodeToPaletteIndex(int eventCode) {
  return reinterpret_cast<int(__cdecl*)(int)>(::MapTurnEventCodeToPaletteIndex)(eventCode);
}
