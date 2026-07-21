// TDiplomacyMapView QuickDraw legend rendering slice.

#include "decomp_types.h"
#include "game/TDiplomacyMapView.h"
#include "game/global_data_tables.h"
#include "game/TView.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/bitmap_descriptor_helpers.h"
#include "game/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/mfc.h"
#include "game/quickdraw_regions.h"
#include "game/TDiplomacyMgr.h"
#include "game/TStrategicMapViewSystem.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/TControl.h"
#include "game/TGlobalMapState.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TInfoBarText.h"
#include "game/ui_control_tags.h"
#include "game/TCountry.h"
#include "game/TInfoPanelView.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/TGreatPower.h"
#include "game/TMilitaryUnit.h"
#include "game/TViewMgr.h"
#include "game/TSimMgr.h"
#include "game/TPanelView.h"
#include "game/ui_text_label_helpers_decls.h"

// Defined below in address order (0x4d5d30).
void __cdecl BuildDiplomacyOverlayHitMaskOpcodeStream(DiplomacyMaskBufferRun* run,
                                                      void* surfacePixels, int flag,
                                                      int surfaceHeight);

undefined4 FrameRegionOnHdcAndReleaseBrushState(void);
undefined4 BlitMonochromeMaskBytePatternToSurface(void);
undefined4 RunDiplomacyWaitSheetPopupAndAwaitResponse(void);

namespace {
const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
const unsigned int kAddrDiplomacyTurnStateManager = 0x006A43D0;
const unsigned int kAddrDiplomacyRelationPaletteMap = 0x00696990;
const unsigned int kAddrDiplomacyHitRectInitialized = 0x006A2FBC;
const unsigned int kAddrDiplomacyHitBounds = 0x006A3008;
const unsigned int kAddrResolveDiplomacyActionValue = 0x004F5F70;

// The Windows port brackets minor-nation label drawing with the palette built from
// bitmap 0x3b6. The original uses an 8-byte compiler-generated guard around
// CDC::SelectPalette; keep that lifetime explicit and exception-safe here.
class ScopedDefaultDibPaletteSelection {
public:
  explicit ScopedDefaultDibPaletteSelection(CDC* dc) : m_dc(dc), m_previousPalette(NULL) {
    if (m_dc != NULL) {
      m_previousPalette =
          m_dc->SelectPalette(g_pModuleLibraryCacheState->EnsureDefaultDibPalette(), FALSE);
    }
  }

  ~ScopedDefaultDibPaletteSelection() {
    if (m_dc != NULL) {
      m_dc->SelectPalette(m_previousPalette, FALSE);
    }
  }

private:
  CDC* m_dc;
  CPalette* m_previousPalette;
};
} // namespace

// FUNCTION: IMPERIALISM 0x00430730
DiplomacyMaskBufferRun::~DiplomacyMaskBufferRun() {
  delete[] maskBytesAt00;
}

// Emits a "write this packed color dword" run into the primary JIT opcode buffer at the
// cursor kept in the secondary buffer's first dword, then executes the assembled blit
// opcodes against the destination surface. StrategicMapCallbackRecord is a game-specific
// JIT blit-code builder (not an MFC collection): dispatchTable00/subobjectDispatchTable1c
// point at game .rdata, the byte buffers are grown through the game's _realloc wrappers,
// and the tail CALLs into the buffer itself.
// FUNCTION: IMPERIALISM 0x004d4bf0
void StrategicMapCallbackRecord::AppendPackedColorDword(int surface, int packedColor) {
  const unsigned int packed = (packedColor & 0xff) * 0x01010101u;

  // The secondary opcode buffer stores the primary-buffer write cursor in its first dword.
  if (cursorBufferSize24 == 0) {
    ownedBuffer20 = new char[sizeof(int)];
    cursorBufferSize24 = sizeof(int);
  }
  if (cursorBufferInitialized28 == 0) {
    cursorBufferInitialized28 = 1;
  }
  const int cursor = *reinterpret_cast<int*>(ownedBuffer20);
  *EnsureOpcodeBufferByteAtIndex(cursor) = static_cast<unsigned char>(packed);
  *EnsureOpcodeBufferByteAtIndex(cursor + 1) = static_cast<unsigned char>(packed >> 8);
  *EnsureOpcodeBufferByteAtIndex(cursor + 2) = static_cast<unsigned char>(packed >> 16);
  *EnsureOpcodeBufferByteAtIndex(cursor + 3) = static_cast<unsigned char>(packed >> 24);

  // Grow the primary buffer to span the generated blit entry, then execute the opcodes.
  // The original hands the destination surface to the generated code in eax, which has no
  // standard C++ calling convention; this is an unavoidable low-level bridge (executing a
  // JIT'd opcode buffer, not a normal-function convention fake).
  unsigned char* entry = EnsureOpcodeBufferByteAtIndex(alignmentCursor14);
  reinterpret_cast<void (*)(int)>(entry)(surface);
}

// FUNCTION: IMPERIALISM 0x004d5cf0
void __cdecl StreamOverlayHitMaskToSurfaceDib(DiplomacyMaskBufferRun* run,
                                              TQuickDrawSurfaceContext* surface, int flag) {
  int height = surface->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
  if (height < 1) {
    height = -height;
  }
  BuildDiplomacyOverlayHitMaskOpcodeStream(
      run, reinterpret_cast<void*>(surface->surfaceDib->m_pInfoHeader->bmiHeader.biWidth), flag,
      height);
}

// Clamps `rect` inside `bounds`, preserving the rect's width/height.

// Streams a nation's packed hit mask into the surface's overlay opcode buffer; body
// not yet ported (1149 bytes) -- claimed as a typed stub so callers link the real
// signature.
// FUNCTION: IMPERIALISM 0x004d5d30
void __cdecl BuildDiplomacyOverlayHitMaskOpcodeStream(DiplomacyMaskBufferRun* run,
                                                      void* surfacePixels, int flag,
                                                      int surfaceHeight) {
  (void)run;
  (void)surfacePixels;
  (void)flag;
  (void)surfaceHeight;
}
// FUNCTION: IMPERIALISM 0x004f3a50
void __cdecl ClampRectWithinBoundsPreservingSize(RECT* rect, RECT* bounds) {
  short width = static_cast<short>(rect->right) - static_cast<short>(rect->left);
  short height = static_cast<short>(rect->bottom) - static_cast<short>(rect->top);
  if (rect->top < bounds->top) {
    rect->top = bounds->top;
    rect->bottom = height + bounds->top;
  }
  if (bounds->bottom < rect->bottom) {
    rect->bottom = bounds->bottom;
    rect->top = bounds->bottom - height;
  }
  if (rect->left < bounds->left) {
    rect->left = bounds->left;
    rect->right = width + bounds->left;
  }
  if (bounds->right < rect->right) {
    rect->right = bounds->right;
    rect->left = bounds->right - width;
  }
}

// SYNTHETIC: IMPERIALISM 0x004f3ae0
// TDiplomacyMapView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f3b60
// TDiplomacyMapView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDiplomacyMapView, TPicture)

// FUNCTION: IMPERIALISM 0x004f3b80
TDiplomacyMapView::TDiplomacyMapView() : TPicture() {
  interactionModeAt94 = 0;
  frameRegionSelectorAt98 = 0;
  selectedTerrainIndexAt90 = 0;
  regionAt9c = 0;
  legendSurfaceModeAt524 = 6;
  stateFlagAtB8 = 0;
  // cursorTable is a shared void* scratch array; slot 5 (0x14 + 5*4 = 0x28) holds a plain
  // flag value (1) here. That is consistent with the array's void* element typing -- each
  // consumer interprets its own slot -- not one field carrying two overlaid meanings.
  g_pUiRuntimeContext->cursorTable[5] = reinterpret_cast<void*>(1);
}

// FUNCTION: IMPERIALISM 0x004f3c70
DiplomacyMaskBufferRun::DiplomacyMaskBufferRun() {
  maskBytesAt00 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004f3c90
// TDiplomacyMapView::`scalar deleting destructor'
// SYNTHETIC: IMPERIALISM 0x004f3cc0
// TDiplomacyMapView::~TDiplomacyMapView

// FUNCTION: IMPERIALISM 0x004f3d60
void TDiplomacyMapView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  BuildDiplomacyNationOverlayGeometryAndHitMasks();
  InitializeDiplomacyMinisterActionControlsAndLabels();
  SetControlHoverHelpText(CString(g_szEmptyString), this);

  if (g_pSimMgr->mode == 6) {
    TView* endControl = ResolveControlByTag(kControlTagEndSpace);
    if (endControl != nullptr) {
      endControl->Free();
    }
    TView* querControl = ResolveControlByTag(kControlTagQuer);
    if (querControl != nullptr) {
      querControl->Free();
    }
    TView* topBControl = ResolveControlByTag(kControlTagTopB);
    if (topBControl != nullptr) {
      topBControl->Free();
    }
    SetPictureResourceIdAndRefresh(0x20d0, 1);
  }
}

// FUNCTION: IMPERIALISM 0x004f3e30
void TDiplomacyMapView::Close() {
  stateFlagAtB8 = 0;
}

// FUNCTION: IMPERIALISM 0x004f3e60
void TDiplomacyMapView::Free() {
  if (regionAt9c != 0) {
    DisposeRgn(regionAt9c);
  }
  regionAt9c = 0;
  TView::Free();
}

// Rebuilds the diplomacy-map nation overlay: merges every nation's clip region into
// regionAt9c, rasterizes each nation's region into a packed 1-bit hit mask, places the
// nation name labels with collision avoidance, and refreshes the per-tile marker rects.
// FUNCTION: IMPERIALISM 0x004f3ea0
void TDiplomacyMapView::BuildDiplomacyNationOverlayGeometryAndHitMasks() {
  short labelWidths[23];
  short labelXs[23];
  short labelYs[23];
  memset(labelWidths, 0, sizeof(labelWidths));
  memset(labelXs, 0, sizeof(labelXs));
  memset(labelYs, 0, sizeof(labelYs));

  regionAt9c = NewRgn();
  for (short terrain = 0; terrain < 0x17; ++terrain) {
    if (g_apTerrainTypeDescriptorTable[terrain] != 0) {
      UnionRgn(regionAt9c, g_pStrategicMapViewSystem->GetClipRegionSlotByIndex(terrain),
               regionAt9c);
    }
  }

  mapOriginPixelX514 = 0x31;
  mapOriginPixelY518 = 0x2d;
  mapExtentPixelX51C = 0x24d;
  mapExtentPixelY520 = 0x159;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b68);

  for (short nationIndex = 0; nationIndex < 0x17; ++nationIndex) {
    DiplomacyMaskBufferRun* run = &maskRuns[nationIndex];
    RgnHandle nationRgn = g_pStrategicMapViewSystem->GetClipRegionSlotByIndex(nationIndex);
    CopyRect(reinterpret_cast<RECT*>(&run->leftAt04), &(*nationRgn)->rgnBBox);
    char* oldMask = reinterpret_cast<char*>(run->maskBytesAt00);
    run->rightAt0c = run->leftAt04 + ((run->rightAt0c - run->leftAt04) + 7 >> 3) * 8;
    operator delete(oldMask);
    char* mask = static_cast<char*>(operator new((run->rightAt0c - run->leftAt04) *
                                                 (run->bottomAt10 - run->topAt08)));
    run->maskBytesAt00 = reinterpret_cast<unsigned char*>(mask);
    for (int y = run->topAt08; y < run->bottomAt10; ++y) {
      for (int x = run->leftAt04; x < run->rightAt0c;) {
        *mask = 0;
        for (int bit = 1; bit < 0x100; bit *= 2) {
          CPoint probe;
          probe.x = x;
          probe.y = y;
          if (PtInRgn(&probe, nationRgn) != 0) {
            *mask = static_cast<char>(*mask + bit);
          }
          ++x;
        }
        ++mask;
      }
    }
    StreamOverlayHitMaskToSurfaceDib(run, g_pPrimaryRenderSurfaceContext, 1);

    CString nationName;
    TCountry* nation = g_apTerrainTypeDescriptorTable[nationIndex];
    if (nation != 0) {
      if (EmptyRgn(g_pStrategicMapViewSystem->GetClipRegionSlotByIndex(nationIndex)) == 0) {
        short anchorTile = nation->GetOrComputeOverlayAnchorTileIndex();
        int labelCenterX = (anchorTile % 0x6c) * 5 + 0x31;
        int labelY = (anchorTile / 0x6c + 9) * 5;
        static_cast<TGreatPower*>(nation)->LoadNationDisplayNameSharedRefFromField8(&nationName);
        short textWidth = MeasureTextExtentWithCachedQuickDrawStyle(&nationName);
        labelY -= 6;
        labelWidths[nationIndex] = textWidth;
        short labelX = static_cast<short>(labelCenterX) - textWidth / 2;

        // Slide the label down (or up) until it no longer overlaps an already placed
        // label; give up after 0x14 nudges.
        short attempts = 0;
        short placedIndex = 0;
        while (placedIndex <= 0x16) {
          short otherWidth = labelWidths[placedIndex];
          if (otherWidth == 0) {
            otherWidth = 0x5a;
          }
          short otherY = labelYs[placedIndex];
          if (static_cast<short>(labelY) >= otherY && static_cast<short>(labelY) <= otherY + 10 &&
              labelX >= labelXs[placedIndex] && labelX <= otherWidth + labelXs[placedIndex]) {
            ++labelY;
            ++attempts;
            if (attempts < 0x14) {
              placedIndex = 0;
              continue;
            }
            ++placedIndex;
            continue;
          }
          if (static_cast<short>(labelY) >= otherY - 10 && static_cast<short>(labelY) <= otherY &&
              labelX >= labelXs[placedIndex] - textWidth && labelX <= labelXs[placedIndex]) {
            --labelY;
            ++attempts;
            if (attempts < 0x14) {
              placedIndex = 0;
              continue;
            }
          }
          ++placedIndex;
        }

        labelYs[nationIndex] = static_cast<short>(labelY);
        labelXs[nationIndex] = labelX;
        RECT* labelRect = &nationLabelRects234[nationIndex];
        labelRect->left = labelX;
        labelRect->top = labelY;
        labelRect->right = labelX + textWidth;
        labelRect->bottom = labelY + 0xc;
        // Reuses this record's opcode-bookkeeping fields (offset 0x08..0x18: bufferCapacity08,
        // committedLength0c, appendCursor10, alignmentCursor14) as scratch RECT storage here,
        // before any opcode data has been written to this slot this session -- the same
        // contiguous-fields-as-RECT idiom DiplomacyMaskBufferRun uses for leftAt04/topAt08/
        // rightAt0c/bottomAt10 above.
        ClampRectWithinBoundsPreservingSize(
            labelRect, reinterpret_cast<RECT*>(&packedColorRuns[nationIndex].bufferCapacity08));
        int markerX = (static_cast<short>(nation->homeRegionIndex) % 0x6c) * 5;
        int markerY = (static_cast<short>(nation->homeRegionIndex) / 0x6c + 9) * 5;
        RECT* anchorRect = &nationAnchorRects3A4[nationIndex];
        anchorRect->left = markerX + 0x29;
        anchorRect->top = markerY - 8;
        anchorRect->right = markerX + 0x39;
        anchorRect->bottom = markerY + 8;
        continue;
      }
    }
    RECT* labelRect = &nationLabelRects234[nationIndex];
    labelRect->left = 0;
    labelRect->top = 0;
    labelRect->right = 0;
    labelRect->bottom = 0;
    RECT* hitRect = &nationTextHitRectsC4[nationIndex];
    hitRect->left = 0;
    hitRect->top = 0;
    hitRect->right = 0;
    hitRect->bottom = 0;
  }

  for (int tile = 0; tile < 0x180; ++tile) {
    tileHasOwnerFlags52C[tile] = 0;
    tileHasOwnerFlags52C[tile] =
        reinterpret_cast<char*>(g_pDiplomacyTurnStateManager)[tile - 0x228] != -1;
    short colX2;
    unsigned short row;
    SplitTileIndexToHexRasterColumnX2AndRow(g_pGlobalMapState->cityScoreTable[tile].cityTileIndex04,
                                            &colX2, &row);
    RECT* tileRect = &tileMarkerRects6AC[tile];
    tileRect->left = (colX2 * 5) / 2 - 4 + mapOriginPixelX514;
    tileRect->top = static_cast<short>(row) * 5 - 3 + mapOriginPixelY518;
    tileRect->right = tileRect->left + 9;
    tileRect->bottom = tileRect->top + 6;
  }

  short activeNation = g_pSimMgr->GetActiveNationId();
  selectedTerrainIndexAt90 = activeNation;
  frameRegionSelectorAt98 = activeNation;
  activeNationC2 = activeNation;
  actionCodeBC = 0xd;
}

// Shared nil-pointer assert used by InitializeDiplomacyMinisterActionControlsAndLabels'
// 6 action-button resolves (0x4f4620, D:\Ambit\Cross\UDiplomacyViews.cpp:0x3a7).
static inline void AssertActionButtonResolved(void* button) {
  if (button == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUDiplomacyViews_00696AE0, 0x3a7);
  }
}

// FUNCTION: IMPERIALISM 0x004f4620
void TDiplomacyMapView::InitializeDiplomacyMinisterActionControlsAndLabels() {
  CString text;

  for (int buttonIndex = 0; buttonIndex < 6; ++buttonIndex) {
    TView* button = ResolveControlByTag(g_diplomacyActionButtonTagTable_00696960[buttonIndex]);
    actionButtonsA0[buttonIndex] = button;
    AssertActionButtonResolved(button);
  }

  TInfoPanelView* infoActionButton = static_cast<TInfoPanelView*>(actionButtonsA0[0]);
  infoActionButton->SetInfoCountry(activeNationC2);
  infoActionButton->Setup();

  for (short i = 0; i < 6; ++i) {
    TView* hoverControl = ResolveControlByTag(g_councilControlTagTable[i]);
    g_pSimMgr->GetString(0x2733, static_cast<short>(i + 0x52), &text);
    SetControlHoverHelpText(text, hoverControl);
  }

  if (g_pSimMgr->mode == 6) {
    TView* trtyHover = ResolveControlByTag(g_councilControlTagTable[1]);
    g_pSimMgr->GetString(0x274a, 5, &text);
    SetControlHoverHelpTextAltEntry(text, trtyHover);

    TView* granHover = ResolveControlByTag(g_councilControlTagTable[2]);
    SetControlHoverHelpTextAltEntry(CString(g_szEmptyString), granHover);

    TView* tradHover = ResolveControlByTag(g_councilControlTagTable[3]);
    SetControlHoverHelpTextAltEntry(CString(g_szEmptyString), tradHover);
  } else {
    TView* offrControl = ResolveControlByTag(g_councilControlTagTable[5]);
    SetControlHoverHelpText(CString(g_szEmptyString), offrControl);
    offrControl->CaptureLayoutF0(g_diplomacyPopupLayoutPosition_006a3020, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004f48c0
void TDiplomacyMapView::ApplyRectSlot110(RECT* rectBuffer) {
  // Constructed and destroyed here (EH state 0 while alive) but never touched in the
  // body -- a dead local in the original, kept for the exact EH/codegen shape.
  CString unusedScratch;

  if (interactionModeAt94 == 1) {
    RebuildDiplomacyLegendPaletteMode1AndBlit(frameRegionSelectorAt98, rectBuffer);
  } else if (interactionModeAt94 == 2) {
    RenderDiplomacyLegendSurfaceAndPresent(rectBuffer);
  } else if (interactionModeAt94 == 4) {
    RebuildDiplomacyLegendPaletteMode4AndBlit(frameRegionSelectorAt98, rectBuffer);
  } else {
    RenderDiplomacyLegendSurfaceAndPresent(rectBuffer);
  }

  SetQuickDrawFillColor(0xffffff);
  RgnHandle frameRegion = g_pStrategicMapViewSystem->GetClipRegionSlotByIndex(
      static_cast<short>(frameRegionSelectorAt98));
  // 0x497860 is a genuine __cdecl free function (ret 0, all args on the stack); this
  // call site's disassembly pushes exactly one argument (unlike the 3-arg cast used at
  // the RenderDiplomacyLegendSurfaceAndPresent call site above) -- only the arg/return
  // types are adjusted here, the convention is not faked.
  reinterpret_cast<void(__cdecl*)(void*)>(FrameRegionOnHdcAndReleaseBrushState)(frameRegion);
  SetQuickDrawFillColor(0);

  if (interactionModeAt94 == 5) {
    DrawVoteNuggets();
  }
  DrawIcons(rectBuffer);
}

// Relation-percentage -> icon-row lookup for interactionModeAt94 == 2 (0x00696950).
namespace {
const short kRelationTierThresholds[7] = {95, 90, 75, 50, 25, 0, 300};
} // namespace

// FUNCTION: IMPERIALISM 0x004f4a30
void TDiplomacyMapView::DrawNames(RECT* presentRect) {
  (void)presentRect; // ignored stack arg threaded through by the caller
  int styleForeground = 0;
  int styleShadow = 0;
  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 10, 0x2b68, 1);
  MapUiThemeCodeToStyleFlags(0x2b68, &styleForeground);
  MapUiThemeCodeToStyleFlags(0x2b6b, &styleShadow);

  // Great powers (slots 0..6): text-only legend labels, drawn as a 1px drop shadow
  // (shadow color at +1,+1) plus the foreground color at the label origin.
  for (int gp = 0; gp < 7; ++gp) {
    TCountry* terrain = g_apTerrainTypeDescriptorTable[gp];
    if (terrain == nullptr) {
      continue;
    }
    RECT* labelRect = &nationLabelRects234[gp];
    if (ProbeRectEmptyAfterCopyToLocal(labelRect) != 0) {
      continue;
    }
    CString label;
    short code = terrain->encodedNationSlot;
    if (code < 100 || code > 199) {
      terrain->FormatOverlayTerrainLabelText(&label);
      MapUiThemeCodeToStyleFlags(0x2b68, &styleForeground);
      MapUiThemeCodeToStyleFlags(0x2b6b, &styleShadow);
    } else {
      terrain->LoadNationDisplayNameSharedRefFromField8(&label);
      MapUiThemeCodeToStyleFlags(0x2b67, &styleForeground);
      MapUiThemeCodeToStyleFlags(0x2b6f, &styleShadow);
    }
    short x = static_cast<short>(labelRect->left);
    short y = static_cast<short>(labelRect->bottom);
    SetQuickDrawColorAndSyncGlobals(styleShadow);
    SetQuickDrawTextOriginWithContextOffset(x + 1, y + 1);
    DrawTextWithCachedQuickDrawStyleState(&label);
    SetQuickDrawColorAndSyncGlobals(styleForeground);
    SetQuickDrawTextOriginWithContextOffset(x, y);
    DrawTextWithCachedQuickDrawStyleState(&label);
  }

  // Minors (slots 7..22): same drop-shadow labels, classified via a theme jump-table.
  static const short kMinorThemeByBand[7] = {0x2b6e, 0x2b69, 0x2b70, 0x2b71,
                                             0x2b72, 0x2b73, 0x2b74};
  for (int mn = 7; mn < 23; ++mn) {
    TCountry* terrain = g_apTerrainTypeDescriptorTable[mn];
    if (terrain == nullptr) {
      continue;
    }
    RECT* labelRect = &nationLabelRects234[mn];
    if (ProbeRectEmptyAfterCopyToLocal(labelRect) != 0) {
      continue;
    }
    CString label;
    short code = terrain->encodedNationSlot;
    if (code == -1) {
      terrain->FormatOverlayTerrainLabelText(&label);
      MapUiThemeCodeToStyleFlags(0x2b6b, &styleForeground);
      MapUiThemeCodeToStyleFlags(0x2b68, &styleShadow);
    } else if (code >= 100 && code < 200) {
      terrain->LoadNationDisplayNameSharedRefFromField8(&label);
      MapUiThemeCodeToStyleFlags(0x2b67, &styleForeground);
      MapUiThemeCodeToStyleFlags(0x2b6f, &styleShadow);
    } else {
      int band;
      if (code >= 200) {
        band = code - 200;
      } else if (code >= 100) {
        band = code - 100; // unreachable given the branch above; kept to match codegen
      } else {
        band = terrain->nationSlot;
      }
      MapUiThemeCodeToStyleFlags(kMinorThemeByBand[band], &styleForeground);
      MapUiThemeCodeToStyleFlags(0x2b68, &styleShadow);
      terrain->FormatOverlayTerrainLabelText(&label);
    }

    ScopedDefaultDibPaletteSelection paletteSelection(GetActiveQuickDrawDc());
    short x = static_cast<short>(labelRect->left);
    short y = static_cast<short>(labelRect->bottom);
    SetQuickDrawColorAndSyncGlobals(styleShadow);
    SetQuickDrawTextOriginWithContextOffset(x + 1, y + 1);
    DrawTextWithCachedQuickDrawStyleState(&label);
    SetQuickDrawColorAndSyncGlobals(styleForeground);
    SetQuickDrawTextOriginWithContextOffset(x, y);
    DrawTextWithCachedQuickDrawStyleState(&label);
  }
}

// FUNCTION: IMPERIALISM 0x004f4ec0
void TDiplomacyMapView::DrawIcons(RECT* presentRect) {
  const short policyIconColumns[5] = {4, 3, 2, 0, 1};

  if (interactionModeAt94 != 1 && interactionModeAt94 != 4 && interactionModeAt94 != 2) {
    return;
  }

  RECT presentRectCopy = *presentRect;
  for (short terrainIndex = 0; terrainIndex < 0x17; ++terrainIndex) {
    if (g_apTerrainTypeDescriptorTable[terrainIndex] == 0) {
      continue;
    }

    RECT* hitRect = &nationTextHitRectsC4[terrainIndex];
    RECT intersection;
    if (SectRect(&presentRectCopy, hitRect, &intersection) == 0) {
      continue;
    }

    bool boycottFlag = false;    // bVar3
    bool offsetOverlayX = false; // bVar4
    short iconOffset = -1;       // sVar9

    short compatValue = g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
        frameRegionSelectorAt98, terrainIndex);
    if (compatValue != 0) {
      short compatIconX = static_cast<short>((compatValue + 0x16) * 0x10);
      RECT compatSrcRect = {compatIconX, 0, static_cast<int>(compatIconX + 0x10), 0x10};
      UpdatePaletteIndexWithDefaultFallback(0x10);
      SetQuickDrawFillColor(0);
      BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas694[2]->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &compatSrcRect, &nationAnchorRects3A4[terrainIndex], 0x24,
                                       0);
      UpdatePaletteIndexWithDefaultFallback(0x13);
    }

    if (interactionModeAt94 == 4) {
      if (g_pDiplomacyTurnStateManager->IsPrimaryNationSlotIndex(frameRegionSelectorAt98)) {
        short need =
            g_apNationStates[frameRegionSelectorAt98]->diplomacyPolicyByNation[terrainIndex];
        if (need == 0x133) {
          iconOffset = 0x150;
        } else if (need == 0x134) {
          iconOffset = 0x160;
        } else if (need != -1) {
          iconOffset = static_cast<short>(policyIconColumns[need] << 4);
        }
      }
    } else if (interactionModeAt94 == 2) {
      short relation =
          g_apTerrainTypeDescriptorTable[frameRegionSelectorAt98]->needLevelByNation[terrainIndex];
      boycottFlag =
          (frameRegionSelectorAt98 < 7) &&
          (g_apNationStates[frameRegionSelectorAt98]->colonyBoycottFlags[terrainIndex] != 0);
      if (relation != 100) {
        for (short tier = 0; tier < 7; ++tier) {
          if (kRelationTierThresholds[tier] == relation) {
            iconOffset = static_cast<short>((tier + 5) * 0x10);
          }
        }
        if (boycottFlag) {
          if (relation == 300) {
            iconOffset = 0x190;
            boycottFlag = false;
          } else {
            offsetOverlayX = true;
          }
        }
      }
    } else { // interactionModeAt94 == 1
      if (g_pDiplomacyTurnStateManager->IsPrimaryNationSlotIndex(frameRegionSelectorAt98)) {
        short need =
            g_apNationStates[frameRegionSelectorAt98]->diplomacyGrantByNation[terrainIndex];
        if (need == 1000) {
          iconOffset = 0xd0;
        } else if (need == 3000) {
          iconOffset = 0xe0;
        } else if (need == 5000) {
          iconOffset = 0xf0;
        } else if (need == 10000) {
          iconOffset = 0x100;
        } else if (need == 0x43e8) {
          iconOffset = 0x110;
        } else if (need == 0x4bb8) {
          iconOffset = 0x120;
        } else if (need == 0x5388) {
          iconOffset = 0x130;
        } else if (need == 0x6710) {
          iconOffset = 0x140;
        }
      }
    }

    if (iconOffset != -1) {
      RECT iconSrcRect = {iconOffset, 0, static_cast<int>(iconOffset + 0x10), 0x10};
      UpdatePaletteIndexWithDefaultFallback(0x10);
      SetQuickDrawFillColor(0);
      BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas694[2]->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &iconSrcRect, hitRect, 0x24, 0);
      UpdatePaletteIndexWithDefaultFallback(0x13);
    }

    if (boycottFlag) {
      RECT boycottSrcRect = {0xc0, 0, 0xd0, 0x10};
      RECT boycottDstRect = *hitRect;
      if (offsetOverlayX) {
        OffsetRect(&boycottDstRect, 0x10, 0);
      }
      UpdatePaletteIndexWithDefaultFallback(0x10);
      SetQuickDrawFillColor(0);
      BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas694[2]->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &boycottSrcRect, &boycottDstRect, 0x24, 0);
      UpdatePaletteIndexWithDefaultFallback(0x13);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004f5410
void TDiplomacyMapView::BeginMouseCaptureAndStartRepeatTimer(const CPoint& point,
                                                             TToolboxEvent* event, CPoint origin) {
  TPicture::BeginMouseCaptureAndStartRepeatTimer(point, event, origin);
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
    // 0x5e7920 is the CRT atexit (libcmt onexit.obj, oracle-confirmed): the original
    // registers the static hit-rect cleanup at 0x4f5f70 as an exit handler.
    atexit(reinterpret_cast<void(__cdecl*)(void)>(kAddrResolveDiplomacyActionValue));
  }

  if (PtInRect(reinterpret_cast<const RECT*>(kAddrDiplomacyHitBounds),
               *reinterpret_cast<const POINT*>(clickPoint)) == 0) {
    return 0;
  }
  if (interactionModeAt94 == 5) {
    return 0;
  }

  CPoint localPoint = this->TransformPointViaSlot138(clickPoint);

  int terrainIndex = 0;
  int* terrainDescriptors = reinterpret_cast<int*>(kAddrTerrainTypeDescriptorTable);
  do {
    if (*terrainDescriptors != 0) {
      char hit = g_pStrategicMapViewSystem->MacViewMgrSlot24(&localPoint,
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
    if (actionCode != 0xd && terrainIndex == selectedTerrainIndexAt90) {
      return 1;
    }
  } else {
    *reinterpret_cast<short*>(self + 0xc2) = static_cast<short>(0xffff);
  }
  return actionCode;
}

// FUNCTION: IMPERIALISM 0x004f5f90
void TDiplomacyMapView::HandleCursorHoverFallback(CPoint* point, RgnHandle hitArg) {
  (void)point;
  (void)hitArg;
}

// FUNCTION: IMPERIALISM 0x004f5fb0
void TDiplomacyMapView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* clickPoint,
                                                                            RgnHandle dispatchArg) {
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
      char regionHit =
          g_pStrategicMapViewSystem->MacViewMgrSlot24(&localPoint, static_cast<short>(hitIndex));
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
        selectedTerrainIndexAt90, *reinterpret_cast<short*>(self + 0xc2), actionCode);

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
    hCursor = g_pUiRuntimeContext->cursorTable[cursorId - TViewMgr::kCursorResourceIdBase];
    applyCursor = true;
  } else if (*reinterpret_cast<short*>(self + 0x52a) != 0x41b) {
    *reinterpret_cast<short*>(self + 0x52a) = 0x41b;
    hCursor = g_pUiRuntimeContext->cursorTable[0x41b - TViewMgr::kCursorResourceIdBase];
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
  CTemporaryRegion surface;
  QueryBounds(const_cast<RECT*>(presentRect));

  if (legendSurfaceModeAt524 != 0) {
    int savedTransparentColor = g_pActiveQuickDrawSurfaceContext->transparentBlitColor;
    int savedQuickDrawColor = g_pActiveQuickDrawSurfaceContext->quickDrawColor;

    TQuickDrawSurfaceContext* previousSurface = 0;
    int contextFlags = 0;
    GetActiveQuickDrawSurfaceContextAndFlags(&previousSurface, &contextFlags);
    SetActiveQuickDrawSurfaceContext(g_pPrimaryRenderSurfaceContext, contextFlags);

    if (previousSurface != g_pPrimaryRenderSurfaceContext) {
      ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(g_pPrimaryRenderSurfaceContext));
    }

    // Original passes the present rect here (mov ecx,[esp+0x58]; thiscall 0x48f3c0),
    // not a null rect.
    ApplyRectSlot110(const_cast<RECT*>(presentRect));

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
    DrawNames(const_cast<RECT*>(presentRect));

    if (previousSurface != g_pPrimaryRenderSurfaceContext) {
      NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(g_pPrimaryRenderSurfaceContext));
    }

    SetActiveQuickDrawSurfaceContext(previousSurface, contextFlags);
    SetQuickDrawColorAndSyncGlobals(savedQuickDrawColor);
    SetGlobalBlitTransparentColorRaw(savedTransparentColor);
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
  RgnHandle frameRegion = g_pStrategicMapViewSystem->GetClipRegionSlotByIndex(
      static_cast<short>(frameRegionSelectorAt98));
  // 0x497860 is a genuine __cdecl free function (ret 0, all args on the stack); only its
  // stub arg/return types are adjusted here -- the convention is not faked.
  reinterpret_cast<void(__cdecl*)(void*, int, void*)>(FrameRegionOnHdcAndReleaseBrushState)(
      this, 0, frameRegion);
  SetQuickDrawFillColor(0);
}

// FUNCTION: IMPERIALISM 0x004f6440
void TDiplomacyMapView::BuildCombinedTerrainTypeRegionMaskAndDispatch() {
  RgnHandle region = NewRgn();

  short terrainIndex = 0;
  void** terrainDescriptors = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
  do {
    if (*terrainDescriptors != 0) {
      RgnHandle frameRegion =
          g_pStrategicMapViewSystem->GetClipRegionSlotByIndex(static_cast<short>(terrainIndex));
      UnionRgn(region, frameRegion, region);
    }
    terrainIndex = static_cast<short>(terrainIndex + 1);
    terrainDescriptors = terrainDescriptors + 1;
  } while (terrainIndex < 0x17);

  this->ForwardMapViewVirtualC4IfPresent(reinterpret_cast<int>(region));
  DisposeRgn(region);
}

// FUNCTION: IMPERIALISM 0x004f64c0
void TDiplomacyMapView::RebuildDiplomacyLegendPaletteMode4AndBlit(int activeNationSlot,
                                                                  const RECT* presentRect) {
  TQuickDrawSurfaceContext* previousSurface = 0;
  int maskState[2] = {0, 0};
  int contextFlags = 0;
  RECT blitRect;
  blitRect.left = presentRect->left;
  blitRect.top = presentRect->top;
  blitRect.right = presentRect->right;
  blitRect.bottom = presentRect->bottom;

  if (legendSurfaceModeAt524 != 4) {
    GetActiveQuickDrawSurfaceContextAndFlags(&previousSurface, &contextFlags);
    SetActiveQuickDrawSurfaceContext(g_pPrimaryRenderSurfaceContext, contextFlags);
    ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(g_pPrimaryRenderSurfaceContext));

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
      // 0x4270e0 (SetUiResourceContextTagWord, thiscall this[0]=arg) is the original's
      // compiler-emitted converting-constructor call for BlitMonochromeMaskBytePatternToSurface's
      // paletteByte argument -- ABI-transparent for a plain int, so passing paletteIndex directly
      // reproduces it exactly with no separate call needed at this call site (and the two below).
      int paletteIndex = g_pUiRuntimeContext->GetColor(static_cast<short>(eventCode));
      maskRuns[nationIndex].BlitMonochromeMaskBytePatternToSurface(
          reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()), paletteIndex,
          maskState, 1);

      int packedColor = g_pUiRuntimeContext->GetColor(0x3f);
      packedColorRuns[nationIndex].AppendPackedColorDword(
          reinterpret_cast<unsigned int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()),
          packedColor);

      nationIndex = static_cast<short>(nationIndex + 1);
    } while (nationIndex < 0x17);

    DrawNames(const_cast<RECT*>(presentRect));
    legendSurfaceModeAt524 = 4;
    NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(g_pPrimaryRenderSurfaceContext));
    SetActiveQuickDrawSurfaceContext(previousSurface, contextFlags);
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
void TDiplomacyMapView::VisitNationSlotsForOverlay(int unusedMode) {
  short nationSlot = 0;
  do {
    ++nationSlot;
  } while (nationSlot < 23);
}

// FUNCTION: IMPERIALISM 0x004f6840
void TDiplomacyMapView::RebuildDiplomacyLegendPaletteMode1AndBlit(int activeNationSlot,
                                                                  const RECT* presentRect) {
  CString str1;
  CString str2;
  CString str3;
  CTemporaryRegion surface;
  frameRegionSelectorAt98 = (short)activeNationSlot;

  TQuickDrawSurfaceContext* previousSurface = 0;
  int maskState[2];
  int contextFlags = 0;
  RECT blitRect;
  blitRect.left = presentRect->left;
  blitRect.top = presentRect->top;
  blitRect.right = presentRect->right;
  blitRect.bottom = presentRect->bottom;

  if (legendSurfaceModeAt524 != 1) {
    GetActiveQuickDrawSurfaceContextAndFlags(&previousSurface, &contextFlags);
    SetActiveQuickDrawSurfaceContext(g_pPrimaryRenderSurfaceContext, contextFlags);
    ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(g_pPrimaryRenderSurfaceContext));

    int terrainIndex = 0;
    void** terrainDescriptors = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
    do {
      if (*terrainDescriptors != 0) {
        short eventCode =
            g_pDiplomacyTurnStateManager->GetRelationTypeSlot68(activeNationSlot, terrainIndex);

        maskState[0] = 0;
        maskState[1] = 0;
        int paletteIndex = g_pUiRuntimeContext->GetColor(static_cast<short>(eventCode + 200));
        maskRuns[terrainIndex].BlitMonochromeMaskBytePatternToSurface(
            reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()), paletteIndex,
            maskState, 1);

        int packedColor = g_pUiRuntimeContext->GetColor(0x3f);
        packedColorRuns[terrainIndex].AppendPackedColorDword(
            reinterpret_cast<unsigned int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()),
            packedColor);
      }
      terrainIndex++;
      terrainDescriptors++;
    } while (terrainIndex < 0x17);

    DrawNames(const_cast<RECT*>(presentRect));
    legendSurfaceModeAt524 = 1;
    NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(g_pPrimaryRenderSurfaceContext));
    SetActiveQuickDrawSurfaceContext(previousSurface, contextFlags);
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
  int paletteIndex = g_pUiRuntimeContext->GetColor(static_cast<short>(eventCode));
  DiplomacyMaskBufferRun* maskRun = &maskRuns[maskIndex];
  maskRun->BlitMonochromeMaskBytePatternToSurface(
      reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()), paletteIndex,
      maskState, 1);

  int packedColor = g_pUiRuntimeContext->GetColor(0x3f);
  StrategicMapCallbackRecord* packedRun = &packedColorRuns[maskIndex];
  packedRun->AppendPackedColorDword(
      reinterpret_cast<int>(g_pActiveQuickDrawSurfaceContext->GetBlitSurface()), packedColor);
}

// FUNCTION: IMPERIALISM 0x004f6bd0
void TDiplomacyMapView::BlitDiplomacyMapEventPaletteMaskToSurface(short maskIndex, int bmpId) {
  TQuickDrawSurfaceContext* surface = g_pActiveQuickDrawSurfaceContext;
  DiplomacyMaskBufferRun* maskRun = &maskRuns[maskIndex];
  CDib* bmpHandle =
      g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(static_cast<unsigned short>(bmpId));

  unsigned char* maskCursor = maskRun->maskBytesAt00;
  if (maskCursor != 0) {
    int srcRowWidth = bmpHandle->m_pInfoHeader->bmiHeader.biWidth;
    int srcRowAdvance = (((srcRowWidth + 3) & 0xfffffffc) - maskRun->rightAt0c) + maskRun->leftAt04;
    int surfaceHeight = surface->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (surfaceHeight < 1) {
      surfaceHeight = -surfaceHeight;
    }
    int row = maskRun->topAt08;
    int rowStride = surface->blitSurface.stride;
    unsigned char* destCursor = static_cast<unsigned char*>(surface->blitSurface.pixelBits) +
                                ((surfaceHeight - row) - 1) * rowStride + maskRun->leftAt04;
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
  int packedColor = g_pUiRuntimeContext->GetColor(0x3f);
  StrategicMapCallbackRecord* packedRun = &packedColorRuns[maskIndex];
  packedRun->AppendPackedColorDword(reinterpret_cast<int>(surface->GetBlitSurface()), packedColor);
}

// Selects a minister action topic: repositions the old/new topic buttons via
// CaptureLayoutF0, toggles the 'ltab'/'rtab' bracket TPicture controls around the new
// selection (and their picture-resource id, 5001/5002 at the ends, 5003-5007 or the
// mode-6 override 8410 in between), refreshes the picture-dependent interaction mode via
// a fixed topic->mode table, and invalidates the map region.
// FUNCTION: IMPERIALISM 0x004f6d90
void TDiplomacyMapView::ChangeSelectedActionTopic(int topicIndex) {
  int newTopic = topicIndex;
  if (g_pSimMgr->mode == 6) {
    if (newTopic == 2 || newTopic == 3) {
      return;
    }
    if (newTopic == 1) {
      newTopic = 5;
    }
  }

  if (stateFlagAtB8 == newTopic) {
    return;
  }

  int layoutPosition[2] = {0x39, 0x320};
  actionButtonsA0[stateFlagAtB8]->CaptureLayoutF0(layoutPosition, 1);
  layoutPosition[1] = 0x162;
  actionButtonsA0[newTopic]->CaptureLayoutF0(layoutPosition, 1);

  TPicture* ltabControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagLtab));
  ltabControl->AssertValid();
  TPicture* rtabControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagRtab));
  rtabControl->AssertValid();

  if (newTopic == 0 || newTopic == 4) {
    ltabControl->SetEnabled(1, 1);
    rtabControl->SetEnabled(0, 1);
    if (newTopic == 0) {
      ltabControl->SetPictureResourceIdAndRefresh(0x1389, 1);
    } else {
      ltabControl->SetPictureResourceIdAndRefresh(0x138a, 1);
    }
  } else {
    ltabControl->SetEnabled(0, 1);
    rtabControl->SetEnabled(1, 1);
    if (g_pSimMgr->mode == 6) {
      rtabControl->SetPictureResourceIdAndRefresh(0x20da, 1);
    } else {
      rtabControl->SetPictureResourceIdAndRefresh(static_cast<short>(newTopic + 0x138a), 1);
    }
  }

  this->InvokeSlot13C();
  stateFlagAtB8 = newTopic;

  switch (newTopic) {
  case 0:
    interactionModeAt94 = 0;
    break;
  case 1:
    interactionModeAt94 = 4;
    break;
  case 2:
    interactionModeAt94 = 1;
    break;
  case 3:
    interactionModeAt94 = 2;
    break;
  case 4:
    interactionModeAt94 = 5;
    break;
  case 5:
    interactionModeAt94 = 0;
    break;
  }

  // All 6 action-topic buttons are TPanelView-family siblings (TInfoPanelView,
  // TTreatiesView, TGrantsView, TTradePanelView, TCouncilPanelView, TOffersPanelView),
  // not TControl -- verified by the zero pushed args at this call in the raw
  // disassembly, matching TPanelView's slot 0x68 stub rather than TControl's 5-arg
  // DispatchPictureResourceCommand at the same vtable byte offset.
  static_cast<TPanelView*>(actionButtonsA0[newTopic])->Setup();

  if (selectedTerrainIndexAt90 != frameRegionSelectorAt98) {
    frameRegionSelectorAt98 = selectedTerrainIndexAt90;
    legendSurfaceModeAt524 = 6;
  }

  InvalidateCityDialogRectRegion(reinterpret_cast<RECT*>(&mapOriginPixelX514), 1);
}

// FUNCTION: IMPERIALISM 0x004f7040
void TDiplomacyMapView::InvalidateAndRunChildWaitSheet(void* arg1, void* arg2, void* arg3,
                                                       void* arg4) {
  ChangeSelectedActionTopic(5);
  reinterpret_cast<void(__fastcall*)(void*, int, void*, void*, void*, void*)>(
      RunDiplomacyWaitSheetPopupAndAwaitResponse)(actionButtonsA0[5], 0, arg1, arg2, arg3, arg4);
}

// FUNCTION: IMPERIALISM 0x004f7080
void TDiplomacyMapView::InvalidateAndForwardTabSwitchToChild(void* arg1, void* arg2, void* arg3) {
  ChangeSelectedActionTopic(5);
  static_cast<TControl*>(actionButtonsA0[5])->BuildInsetContentRect(reinterpret_cast<RECT*>(arg1));
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
      ChangeSelectedActionTopic(tabIndex);
      return;
    }
  } else {
    TControl::HandleEvent(commandId, panelEvent, extra);
  }
}

// FUNCTION: IMPERIALISM 0x004f7130
void TDiplomacyMapView::ForwardParam(int param) {
  if (stateFlagAtB8 == 5) {
    actionButtonsA0[5]->ForwardParam(param);
    return;
  }
  // Non-virtual call to TEventHandler::ForwardParam's body (orig routes through the
  // ILT thunk at 0x401d61 -> 0x48a380); the qualified call forces static dispatch.
  TEventHandler::ForwardParam(param);
}

// FUNCTION: IMPERIALISM 0x004f71a0
void TDiplomacyMapView::DrawVoteNuggets() {
  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithDefaultFallback(0x10);

  short selectedTier = visibleVoteTier528;
  int policyIndex = 0;
  do {
    short tierValue = g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix484[policyIndex];
    int iconCode = g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix304[policyIndex];
    if (tileHasOwnerFlags52C[policyIndex] && iconCode != -1 && tierValue <= selectedTier) {
      RECT* iconRect = &tileMarkerRects6AC[policyIndex];
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

      CDib* activeDib = g_pActiveQuickDrawSurfaceContext->surfaceDib;
      if (activeDib != 0) {
        int surfaceHeight = activeDib->m_pInfoHeader->bmiHeader.biHeight;
        if (surfaceHeight < 1) {
          surfaceHeight = -surfaceHeight;
        }
        OffsetRect(&destRect, 0, (surfaceHeight - destRect.top) - destRect.bottom);
      }

      BlitQuickDrawSurfaces(g_pStrategicMapViewSystem->atlas6b8->GetBlitSurface(),
                            g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect, &destRect,
                            0x24);

      destRect.left = iconRect->left - 1;
      destRect.top = iconRect->top - 1;
      destRect.right = iconRect->right + 1;
      destRect.bottom = iconRect->bottom + 1;
      if (tierValue == selectedTier) {
        g_pUiRuntimeContext->ApplyLegendSplitSlot34(6);
      } else {
        SetQuickDrawFillColor(0xffffff);
      }
      QDFrameRect(&destRect);
      SetQuickDrawFillColor(0);
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(destRect.right),
                                              static_cast<short>(destRect.top));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(destRect.right),
                                   static_cast<short>(destRect.bottom));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(destRect.left),
                                   static_cast<short>(destRect.bottom));
    }
    policyIndex += 1;
  } while (policyIndex < 0x180);

  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// 0x005DA040 and 0x005DA180 moved to TViewMgr::HandleTurnEventVtableSlot60ActivateMainDialog
// / HandleTurnEvent2260_RefreshMainHudTitles (src/game/TViewMgr.cpp): the vtable
// evidence (`just vtable TViewMgr`) shows both are TViewMgr's own vtable slots 0x60/0x64, not
// TDiplomacyMapView methods -- neither body ever reads `this`, and this class's prior
// attribution called TView::SetHoverHelpText with an implicit (wrong) `this` receiver
// instead of the real disassembly's explicitly-resolved 'main' control.
