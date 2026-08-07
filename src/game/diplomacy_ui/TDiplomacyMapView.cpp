// TDiplomacyMapView QuickDraw legend rendering slice.

#include "decomp_types.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/diplomacy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"
#include "game/quickdraw_guards.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/ui_core/TControl.h"
#include "game/gfx/CDib.h"
#include "game/map/TMapMgr.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/city_ui/TCountry.h"
#include "game/diplomacy_ui/TInfoPanelView.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/app/ui_resource_builder.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/nation/TGreatPower.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/app/TPanelView.h"
#include "game/diplomacy_ui/TOffersPanelView.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_widgets/TToolBarCluster.h"

namespace {
const unsigned int kAddrDiplomacyTurnStateManager = 0x006A43D0;

#ifdef IMPERIALISM_RUNTIME_TESTS
short g_runtimePolicyIconOffsetByNation[kNationSlotCount];
short g_runtimeSemanticDiplomacyNation = -1;
#endif

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

void ShowDiplomacyActionRejectedNotice();

// FUNCTION: IMPERIALISM 0x00430730
DiplomacyMaskBufferRun::~DiplomacyMaskBufferRun() {
  delete[] maskBytesAt00;
}

// Clamps `rect` inside `bounds`, preserving the rect's width/height.

// Is the mask pixel set, and is it on the region's edge? With `edgeOnly` clear this is
// just the pixel test; with it set, a pixel whose four orthogonal neighbours are all set is
// interior and reports false, leaving only the outline. Retail expands IsMaskPixelSet at
// all five sites, which is why it lives in the header.
// FUNCTION: IMPERIALISM 0x004d5a90
bool IsMaskPixelSetAndOnRegionEdge(int x, int y, DiplomacyMaskBufferRun* run, char edgeOnly) {
  bool isSet = run->IsMaskPixelSet(x, y);
  if (isSet && edgeOnly != '\0') {
    if (run->IsMaskPixelSet(x + 1, y)) {
      if (run->IsMaskPixelSet(x - 1, y)) {
        if (run->IsMaskPixelSet(x, y + 1)) {
          if (run->IsMaskPixelSet(x, y - 1)) {
            return false;
          }
        }
      }
    }
    isSet = true;
  }
  return isSet;
}

// Shared nil-pointer assert used by InitializeDiplomacyMinisterActionControlsAndLabels'
// 6 action-button resolves (0x4f4620, D:\Ambit\Cross\UDiplomacyViews.cpp:0x3a7).
static inline void AssertActionButtonResolved(void* button) {
  if (button == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUDiplomacyViews_00696AE0, 0x3a7);
  }
}
// FUNCTION: IMPERIALISM 0x004f3a50
void __cdecl ClampRectWithinBoundsPreservingSize(RECT* rect, RECT* bounds) {
  short width = static_cast<short>(rect->right) - static_cast<short>(rect->left);
  short height = static_cast<short>(rect->bottom) - static_cast<short>(rect->top);
  int edge = bounds->top;
  if (rect->top < edge) {
    rect->top = edge;
    rect->bottom = height + edge;
  }
  edge = bounds->bottom;
  if (edge < rect->bottom) {
    rect->bottom = edge;
    rect->top = edge - height;
  }
  edge = bounds->left;
  if (rect->left < edge) {
    rect->left = edge;
    rect->right = width + edge;
  }
  edge = bounds->right;
  if (edge < rect->right) {
    rect->right = edge;
    rect->left = edge - width;
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
  g_pAmbitApplication->cursorRegionInvalid = TRUE;
}

// FUNCTION: IMPERIALISM 0x004f3c70
DiplomacyMaskBufferRun::DiplomacyMaskBufferRun() {
  maskBytesAt00 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004f3c90
// TDiplomacyMapView::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004f3d60
void TDiplomacyMapView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  BuildDiplomacyNationOverlayGeometryAndHitMasks();
  InitializeDiplomacyMinisterActionControlsAndLabels();
  SetControlHoverHelpText(CString(g_szEmptyString), this);

  if (g_pSimMgr->mode == 6) {
    TView* endControl = ResolveControlByTag(kControlTagEnd);
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
  g_pAmbitApplication->cursorRegionInvalid = FALSE;
  TView::Close();
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
      UnionRgn(regionAt9c, g_pMacViewMgr->GetClipRegionSlotByIndex(terrain), regionAt9c);
    }
  }

  mapViewportRect514.left = 0x31;
  mapViewportRect514.top = 0x2d;
  mapViewportRect514.right = 0x24d;
  mapViewportRect514.bottom = 0x159;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b68);

  for (short nationIndex = 0; nationIndex < 0x17; ++nationIndex) {
    DiplomacyMaskBufferRun* run = &maskRuns[nationIndex];
    RgnHandle nationRgn = g_pMacViewMgr->GetClipRegionSlotByIndex(nationIndex);
    (*nationRgn)->RefreshBoundingBox();
    CopyRect(&run->boundsAt04, &(*nationRgn)->rgnBBox);
    run->boundsAt04.right =
        run->boundsAt04.left + (((run->boundsAt04.right - run->boundsAt04.left) + 7) >> 3) * 8;
    delete[] run->maskBytesAt00;
    run->maskBytesAt00 = new unsigned char[(run->boundsAt04.right - run->boundsAt04.left) *
                                           (run->boundsAt04.bottom - run->boundsAt04.top)];
    unsigned char* mask = run->maskBytesAt00;
    for (int y = run->boundsAt04.top; y < run->boundsAt04.bottom; ++y) {
      for (int x = run->boundsAt04.left; x < run->boundsAt04.right;) {
        *mask = 0;
        for (int bit = 1; bit < 0x100; bit *= 2) {
          CPoint probe;
          probe.x = x;
          probe.y = y;
          if (PtInRgn(&probe, nationRgn) != 0) {
            *mask = static_cast<unsigned char>(*mask + bit);
          }
          ++x;
        }
        ++mask;
      }
    }
    packedColorRuns[nationIndex].StreamOverlayHitMaskToSurfaceDib(
        run, g_pPrimaryRenderSurfaceContext, 1);

    CString nationName;
    TCountry* nation = g_apTerrainTypeDescriptorTable[nationIndex];
    if (nation != 0) {
      if (EmptyRgn(g_pMacViewMgr->GetClipRegionSlotByIndex(nationIndex)) == 0) {
        short anchorTile = nation->GetOrComputeOverlayAnchorTileIndex();
        int labelCenterX = (anchorTile % 0x6c) * 5 + 0x31;
        int labelY = (anchorTile / 0x6c + 9) * 5;
        nation->LoadNationDisplayNameSharedRefFromField8(&nationName);
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
        ClampRectWithinBoundsPreservingSize(labelRect, &mapViewportRect514);

        CPoint labelProbe(labelCenterX, (anchorTile / 0x6c + 9) * 5 + 8);
        RECT* hitRect = &nationTextHitRectsC4[nationIndex];
        hitRect->left = labelCenterX - 8;
        hitRect->right = labelCenterX + 8;
        if (PtInRgn(&labelProbe, nationRgn) != 0) {
          hitRect->top = labelProbe.y;
          hitRect->bottom = labelProbe.y + 0x10;
        } else {
          hitRect->top = labelProbe.y - 0x20;
          hitRect->bottom = labelProbe.y - 0x10;
        }
        ClampRectWithinBoundsPreservingSize(hitRect, &mapViewportRect514);

        int markerX = (static_cast<short>(nation->homeTileIndex) % 0x6c) * 5;
        int markerY = (static_cast<short>(nation->homeTileIndex) / 0x6c + 9) * 5;
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
    tileHasOwnerFlags52C[tile] = g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix[tile] != -1;
    short colX2;
    unsigned short row;
    SplitTileIndexToHexRasterColumnX2AndRow(g_pGlobalMapState->cityScoreTable[tile].cityTileIndex04,
                                            &colX2, &row);
    RECT* tileRect = &tileMarkerRects6AC[tile];
    tileRect->left = (colX2 * 5) / 2 - 4 + mapViewportRect514.left;
    tileRect->top = static_cast<short>(row) * 5 - 3 + mapViewportRect514.top;
    tileRect->right = tileRect->left + 9;
    tileRect->bottom = tileRect->top + 6;
  }

  short activeNation = g_pSimMgr->GetActiveNationId();
  selectedTerrainIndexAt90 = activeNation;
  frameRegionSelectorAt98 = activeNation;
  activeNationC2 = activeNation;
  actionCodeBC = kDipActionInspectNation;
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
    TView* hoverControl = ResolveControlByTag(g_aDiplomacyActionTopicTabTags[i]);
    g_pSimMgr->GetString(0x2733, static_cast<short>(i + 0x52), &text);
    SetControlHoverHelpText(text, hoverControl);
  }

  if (g_pSimMgr->mode == 6) {
    TView* trtyHover = ResolveControlByTag(g_aDiplomacyActionTopicTabTags[1]);
    g_pSimMgr->GetString(0x274a, 5, &text);
    SetControlHoverHelpTextAltEntry(text, trtyHover);

    TView* granHover = ResolveControlByTag(g_aDiplomacyActionTopicTabTags[2]);
    SetControlHoverHelpTextAltEntry(CString(g_szEmptyString), granHover);

    TView* tradHover = ResolveControlByTag(g_aDiplomacyActionTopicTabTags[3]);
    SetControlHoverHelpTextAltEntry(CString(g_szEmptyString), tradHover);
  } else {
    TView* offrControl = ResolveControlByTag(g_aDiplomacyActionTopicTabTags[5]);
    SetControlHoverHelpText(CString(g_szEmptyString), offrControl);
    offrControl->Locate(g_diplomacyPopupOffscreenPosition_006a3020, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004f48c0
void TDiplomacyMapView::Draw(RECT* rectBuffer) {
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
  RgnHandle frameRegion =
      g_pMacViewMgr->GetClipRegionSlotByIndex(static_cast<short>(frameRegionSelectorAt98));
  QDFrameRgn(frameRegion);
  SetQuickDrawFillColor(0);

  if (interactionModeAt94 == 5) {
    DrawVoteNuggets();
  }
  DrawIcons(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x004f4a30
void TDiplomacyMapView::DrawNames(const RECT* presentRect) {
  (void)presentRect; // ignored stack arg threaded through by the caller
  COLORREF styleForeground = 0;
  COLORREF styleShadow = 0;
  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 10, 0x2b68, 1);
  ResolveUiThemeColor(0x2b68, &styleForeground);
  ResolveUiThemeColor(0x2b6b, &styleShadow);

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
      ResolveUiThemeColor(0x2b68, &styleForeground);
      ResolveUiThemeColor(0x2b6b, &styleShadow);
    } else {
      terrain->LoadNationDisplayNameSharedRefFromField8(&label);
      ResolveUiThemeColor(0x2b67, &styleForeground);
      ResolveUiThemeColor(0x2b6f, &styleShadow);
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
      ResolveUiThemeColor(0x2b6b, &styleForeground);
      ResolveUiThemeColor(0x2b68, &styleShadow);
    } else if (code >= 100 && code < 200) {
      terrain->LoadNationDisplayNameSharedRefFromField8(&label);
      ResolveUiThemeColor(0x2b67, &styleForeground);
      ResolveUiThemeColor(0x2b6f, &styleShadow);
    } else {
      int band;
      if (code >= 200) {
        band = code - 200;
      } else if (code >= 100) {
        band = code - 100; // unreachable given the branch above; kept to match codegen
      } else {
        band = terrain->nationSlot;
      }
      ResolveUiThemeColor(kMinorThemeByBand[band], &styleForeground);
      ResolveUiThemeColor(0x2b68, &styleShadow);
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
      BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas694[2]->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &compatSrcRect, &nationAnchorRects3A4[terrainIndex], 0x24,
                                       0);
      UpdatePaletteIndexWithDefaultFallback(0x13);
    }

    if (interactionModeAt94 == 4) {
      if (g_pDiplomacyTurnStateManager->IsGreatPower(frameRegionSelectorAt98)) {
        short need =
            g_apNationStates[frameRegionSelectorAt98]->diplomacyPolicyByNation[terrainIndex];
        if (need == 0x133) {
          iconOffset = 0x150;
        } else if (need == 0x134) {
          iconOffset = 0x160;
        } else if (need != -1) {
          iconOffset =
              static_cast<short>(policyIconColumns[need - kDiplomacyProposalJoinEmpire] << 4);
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
          if (g_awDiplomacyTradePolicyIconValueTable[tier] == relation) {
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
      if (g_pDiplomacyTurnStateManager->IsGreatPower(frameRegionSelectorAt98)) {
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

#ifdef IMPERIALISM_RUNTIME_TESTS
    g_runtimePolicyIconOffsetByNation[terrainIndex] = iconOffset;
#endif

    if (iconOffset != -1) {
      RECT iconSrcRect = {iconOffset, 0, static_cast<int>(iconOffset + 0x10), 0x10};
      UpdatePaletteIndexWithDefaultFallback(0x10);
      SetQuickDrawFillColor(0);
      BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas694[2]->GetBlitSurface(),
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
      BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas694[2]->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &boycottSrcRect, &boycottDstRect, 0x24, 0);
      UpdatePaletteIndexWithDefaultFallback(0x13);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004f5410
void TDiplomacyMapView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)event;
  (void)origin;

  CRect invalidRect;
  CRect recurringGrantRect;
  unsigned char grantUpdated;
  unsigned char policyUpdated;
  eDipAction action = ResolveDiplomacyActionFromClickAndUpdateTarget(&point);

  switch (action) {
  case kDipActionJoinEmpire: {
    if (g_apNationStates[selectedTerrainIndexAt90]->diplomacyPolicyByNation[activeNationC2] ==
        kDiplomacyProposalJoinEmpire) {
      g_apNationStates[selectedTerrainIndexAt90]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
          activeNationC2, -1);
      break;
    }
    if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
            selectedTerrainIndexAt90, activeNationC2, action)) {
      goto reject_action;
    }
    if (!CheckEntanglements(activeNationC2, action)) {
      goto clear_action;
    }
    g_apNationStates[selectedTerrainIndexAt90]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
        activeNationC2, kDiplomacyProposalJoinEmpire);
    break;
  }
  case kDipActionAlliance: {
    if (g_apNationStates[selectedTerrainIndexAt90]->diplomacyPolicyByNation[activeNationC2] ==
        kDiplomacyProposalAlliance) {
      g_apNationStates[selectedTerrainIndexAt90]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
          activeNationC2, -1);
      break;
    }
    if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
            selectedTerrainIndexAt90, activeNationC2, action)) {
      goto reject_action;
    }
    if (!CheckEntanglements(activeNationC2, action)) {
      goto clear_action;
    }
    g_apNationStates[selectedTerrainIndexAt90]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
        activeNationC2, kDiplomacyProposalAlliance);
    break;
  }
  case kDipActionNonAggressionPact: {
    if (g_apNationStates[selectedTerrainIndexAt90]->diplomacyPolicyByNation[activeNationC2] ==
        kDiplomacyProposalNonAggressionPact) {
      g_apNationStates[selectedTerrainIndexAt90]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
          activeNationC2, -1);
      break;
    }
    if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
            selectedTerrainIndexAt90, activeNationC2, action)) {
      goto reject_action;
    }
    g_apNationStates[selectedTerrainIndexAt90]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
        activeNationC2, kDiplomacyProposalNonAggressionPact);
    break;
  }
  case kDipActionPeaceTreaty: {
    if (g_apNationStates[selectedTerrainIndexAt90]->diplomacyPolicyByNation[activeNationC2] ==
        kDiplomacyProposalPeaceTreaty) {
      g_apNationStates[selectedTerrainIndexAt90]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
          activeNationC2, -1);
      break;
    }
    if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
            selectedTerrainIndexAt90, activeNationC2, action)) {
      goto reject_action;
    }
    g_apNationStates[selectedTerrainIndexAt90]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
        activeNationC2, kDiplomacyProposalPeaceTreaty);
    break;
  }
  case kDipActionDeclareWar: {
    if (g_apNationStates[selectedTerrainIndexAt90]->diplomacyPolicyByNation[activeNationC2] ==
        kDiplomacyProposalDeclareWar) {
      g_apNationStates[selectedTerrainIndexAt90]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
          activeNationC2, -1);
      break;
    }
    if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
            selectedTerrainIndexAt90, activeNationC2, action)) {
      goto reject_action;
    }
    g_apNationStates[selectedTerrainIndexAt90]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
        activeNationC2, kDiplomacyProposalDeclareWar);
    break;
  }
  case kDipActionOneTimeGrant: {
    if (g_apNationStates[selectedTerrainIndexAt90]->diplomacyGrantByNation[activeNationC2] ==
        g_awDiplomacyGrantValueTable[selectedGrantRowC0]) {
      grantUpdated = g_apNationStates[selectedTerrainIndexAt90]
                         ->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(activeNationC2, -1);
    } else {
      if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
              selectedTerrainIndexAt90, activeNationC2, action)) {
        goto reject_one_time_validation;
      }
      grantUpdated = g_apNationStates[selectedTerrainIndexAt90]
                         ->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(
                             activeNationC2, g_awDiplomacyGrantValueTable[selectedGrantRowC0]);
      if (!grantUpdated) {
        g_pDiplomacyTurnStateManager->proposalArrayMode = 0x17;
        ShowDiplomacyActionRejectedNotice();
        action = kDipActionNone;
        goto finish_one_time_grant;
      }
    }
    goto finish_one_time_grant;
  reject_one_time_validation:
    ShowDiplomacyActionRejectedNotice();
    action = kDipActionNone;
    grantUpdated = 0;
  finish_one_time_grant:
    if (!grantUpdated) {
      break;
    }
    invalidRect.left = 0x32;
    invalidRect.top = 0x17c;
    invalidRect.right = 0xe6;
    invalidRect.bottom = 0x190;
    InvalidateCityDialogRectRegion(&invalidRect, 1);
    goto refresh_toolbar;
  }
  case kDipActionRecurringGrant: {
    short grantValue =
        static_cast<short>(g_awDiplomacyGrantValueTable[selectedGrantRowC0] | 0x4000);
    if (g_apNationStates[selectedTerrainIndexAt90]->diplomacyGrantByNation[activeNationC2] ==
        grantValue) {
      grantUpdated = g_apNationStates[selectedTerrainIndexAt90]
                         ->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(activeNationC2, -1);
    } else {
      if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
              selectedTerrainIndexAt90, activeNationC2, action)) {
        goto reject_recurring_validation;
      }
      grantUpdated =
          g_apNationStates[selectedTerrainIndexAt90]
              ->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(activeNationC2, grantValue);
      if (!grantUpdated) {
        g_pDiplomacyTurnStateManager->proposalArrayMode = 0x17;
        ShowDiplomacyActionRejectedNotice();
        action = kDipActionNone;
        goto finish_recurring_grant;
      }
    }
    goto finish_recurring_grant;
  reject_recurring_validation:
    ShowDiplomacyActionRejectedNotice();
    action = kDipActionNone;
    grantUpdated = 0;
  finish_recurring_grant:
    if (!grantUpdated) {
      break;
    }
    recurringGrantRect.left = 0x32;
    recurringGrantRect.top = 0x17c;
    recurringGrantRect.right = 0xe6;
    recurringGrantRect.bottom = 0x190;
    InvalidateCityDialogRectRegion(&recurringGrantRect, 1);
    goto refresh_toolbar;
  }
  case kDipActionTradeSubsidy:
  case kDipActionTradePolicy:
  case kDipActionBoycott: {
    if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
            selectedTerrainIndexAt90, activeNationC2, action)) {
      goto reject_action;
    }

    if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) == 0 || activeNationC2 < 7) {
      short policyValue = g_awDiplomacyTradePolicyIconValueTable[selectedGrantRowC0];
      if (g_apNationStates[selectedTerrainIndexAt90]->needLevelByNation[activeNationC2] ==
          policyValue) {
        g_apNationStates[selectedTerrainIndexAt90]->SetTradePolicyTo(activeNationC2, 100);
      } else {
        g_apNationStates[selectedTerrainIndexAt90]->SetTradePolicyTo(activeNationC2, policyValue);
      }
    } else {
      g_apNationStates[selectedTerrainIndexAt90]->SetTradePolicyTo(activeNationC2, 100);
      for (int policyIndex = 0; policyIndex < 6; ++policyIndex) {
        if (g_pDiplomacyTurnStateManager->GetFavoriteTradePartner(activeNationC2) ==
            selectedTerrainIndexAt90) {
          break;
        }
        g_apNationStates[selectedTerrainIndexAt90]->SetTradePolicyTo(
            activeNationC2, g_awDiplomacyTradePolicyIconValueTable[policyIndex]);
      }
    }
    break;
  }
  reject_action:
    ShowDiplomacyActionRejectedNotice();
  clear_action:
    action = kDipActionNone;
    break;
  case kDipActionInspectNation: {
    if (frameRegionSelectorAt98 != activeNationC2) {
      frameRegionSelectorAt98 = activeNationC2;
      static_cast<TInfoPanelView*>(actionButtonsA0[0])->SetInfoCountry(activeNationC2);
      static_cast<TInfoPanelView*>(actionButtonsA0[0])->Setup();
      legendSurfaceModeAt524 = 6;
      InvalidateCityDialogRectRegion(&mapViewportRect514, 1);
    }
    break;
  }
  case kDipActionBuildEmbassy: {
    if (g_apNationStates[selectedTerrainIndexAt90]->diplomacyPolicyByNation[activeNationC2] ==
        kDiplomacyProposalBuildEmbassy) {
      policyUpdated = g_apNationStates[selectedTerrainIndexAt90]
                          ->ApplyDiplomacyPolicyStateForTargetWithCostChecks(activeNationC2, -1);
    } else {
      if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
              selectedTerrainIndexAt90, activeNationC2, action)) {
        goto reject_policy_action;
      }
      policyUpdated = g_apNationStates[selectedTerrainIndexAt90]
                          ->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
                              activeNationC2, kDiplomacyProposalBuildEmbassy);
    }
    goto finish_policy_update;
  }
  case kDipActionBuildConsulate: {
    if (g_apNationStates[selectedTerrainIndexAt90]->diplomacyPolicyByNation[activeNationC2] ==
        kDiplomacyProposalBuildConsulate) {
      policyUpdated = g_apNationStates[selectedTerrainIndexAt90]
                          ->ApplyDiplomacyPolicyStateForTargetWithCostChecks(activeNationC2, -1);
    } else {
      if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
              selectedTerrainIndexAt90, activeNationC2, action)) {
        goto reject_policy_action;
      }
      policyUpdated = g_apNationStates[selectedTerrainIndexAt90]
                          ->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
                              activeNationC2, kDiplomacyProposalBuildConsulate);
    }
    goto finish_policy_update;
  }
  reject_policy_action:
    ShowDiplomacyActionRejectedNotice();
    action = kDipActionNone;
    policyUpdated = 0;
  finish_policy_update:
    if (policyUpdated) {
      goto refresh_toolbar;
    }
    break;
  case kDipActionLinkTradePolicy: {
    TCountry* targetNation = g_apTerrainTypeDescriptorTable[activeNationC2];
    short controllingNation = targetNation->encodedNationSlot;
    if (controllingNation >= 200) {
      controllingNation = static_cast<short>(controllingNation - 200);
    } else if (controllingNation >= 100) {
      controllingNation = static_cast<short>(controllingNation - 100);
    } else {
      controllingNation = targetNation->nationSlot;
    }
    if (controllingNation != selectedTerrainIndexAt90) {
      TGreatPower* sourceNation = g_apNationStates[selectedTerrainIndexAt90];
      sourceNation->SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(
          activeNationC2, sourceNation->colonyBoycottFlags[activeNationC2] == 0);
    }
    break;
  }
  default:
    break;
  }
  goto finalize_action;

refresh_toolbar: {
  TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(ResolveControlByTag(kControlTagTool));
  toolbar->AssertValid();
  toolbar->UpdateControlTagTreaTextFromNationAndMapContext(g_pSimMgr->GetActiveNationId());
}

finalize_action:
  if (action != kDipActionNone && activeNationC2 != -1) {
    invalidRect = nationTextHitRectsC4[activeNationC2];
    invalidRect.right += 0x10;
    g_pSfxPlaybackSystem->PlaySoundEffect(4000, 0, 1);
    InvalidateCityDialogRectRegion(&invalidRect, 1);
  }
}

// FUNCTION: IMPERIALISM 0x004f5e00
eDipAction TDiplomacyMapView::ResolveDiplomacyActionFromClickAndUpdateTarget(CPoint* clickPoint) {
#ifdef IMPERIALISM_RUNTIME_TESTS
  if (g_runtimeSemanticDiplomacyNation >= 0) {
    int terrainIndex = g_runtimeSemanticDiplomacyNation;
    activeNationC2 = static_cast<short>(terrainIndex);
    if (actionCodeBC != kDipActionInspectNation && terrainIndex == selectedTerrainIndexAt90) {
      return kDipActionSelectedNation;
    }
    return actionCodeBC;
  }
#endif
  static CRect diplomacyHitBounds;
  static bool diplomacyHitBoundsInitialized = false;
  if (!diplomacyHitBoundsInitialized) {
    diplomacyHitBoundsInitialized = true;
    CRect initialBounds(0x31, 0x2d, 0x24d, 0x159);
    CopyRect(&diplomacyHitBounds, &initialBounds);
  }

  if (PtInRect(&diplomacyHitBounds, *clickPoint) == 0) {
    return kDipActionNone;
  }
  if (interactionModeAt94 == 5) {
    return kDipActionNone;
  }

  CPoint localPoint = this->ViewToQDPt(clickPoint);

  int terrainIndex = 0;
  do {
    if (g_apTerrainTypeDescriptorTable[terrainIndex] != 0) {
      char hit =
          g_pMacViewMgr->IsPointInsideClipRegionSlot(&localPoint, static_cast<short>(terrainIndex));
      if (hit != 0) {
        break;
      }
    }
    terrainIndex += 1;
  } while (terrainIndex < kNationSlotCount);

  eDipAction action = kDipActionNone;
  if (terrainIndex < kNationSlotCount) {
    action = actionCodeBC;
    activeNationC2 = static_cast<short>(terrainIndex);
    if (action != kDipActionInspectNation && terrainIndex == selectedTerrainIndexAt90) {
      return kDipActionSelectedNation;
    }
  } else {
    activeNationC2 = -1;
  }
  return action;
}

// FUNCTION: IMPERIALISM 0x004f5f90
void TDiplomacyMapView::DoSetCursor(CPoint* point, RgnHandle hitArg) {
  (void)point;
  (void)hitArg;
}

// FUNCTION: IMPERIALISM 0x004f5fb0
void TDiplomacyMapView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* clickPoint,
                                                                            RgnHandle dispatchArg) {
  CPoint localPoint;
  localPoint.x = clickPoint->x;
  localPoint.y = clickPoint->y;

  short cursorIdsByAction[16];
  cursorIdsByAction[0] = 0x41b;
  cursorIdsByAction[1] = 0x41b;
  cursorIdsByAction[2] = 0x408;
  cursorIdsByAction[3] = 0x407;
  cursorIdsByAction[4] = 0x406;
  cursorIdsByAction[5] = 0x404;
  cursorIdsByAction[6] = 0x405;
  cursorIdsByAction[7] = 0x411;
  cursorIdsByAction[8] = 0x415;
  cursorIdsByAction[9] = 0x409;
  cursorIdsByAction[10] = 0x41b;
  cursorIdsByAction[11] = 0x40f;
  cursorIdsByAction[12] = 0x410;
  cursorIdsByAction[13] = 0x3f3;
  cursorIdsByAction[14] = 0x419;
  cursorIdsByAction[15] = 0x41a;

  int hitIndex = 0;
  bool hit = false;
  do {
    if (g_apTerrainTypeDescriptorTable[static_cast<short>(hitIndex)] != 0) {
      char regionHit =
          g_pMacViewMgr->IsPointInsideClipRegionSlot(&localPoint, static_cast<short>(hitIndex));
      if (regionHit != 0) {
        hit = true;
        break;
      }
    }
    hitIndex += 1;
  } while (static_cast<short>(hitIndex) < 0x17);

  HCURSOR hCursor;
  bool applyCursor = false;
  if (hit) {
    eDipAction action = ResolveDiplomacyActionFromClickAndUpdateTarget(clickPoint);
    bool valid =
        g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
            selectedTerrainIndexAt90, activeNationC2, action);

    short cursorId;
    if (valid == 0) {
      cursorId = 0x41b;
    } else {
      cursorId = cursorIdsByAction[action];
      if (action == kDipActionTradeSubsidy || action == kDipActionOneTimeGrant ||
          action == kDipActionRecurringGrant) {
        cursorId = static_cast<short>(cursorId + selectedGrantRowC0);
      }
    }
    currentCursorResourceId52A = cursorId;
    hCursor = g_pViewMgr->turnEventCursors[cursorId - TViewMgr::kCursorResourceIdBase];
    applyCursor = true;
  } else if (currentCursorResourceId52A != 0x41b) {
    currentCursorResourceId52A = 0x41b;
    hCursor = g_pViewMgr->turnEventCursors[0x41b - TViewMgr::kCursorResourceIdBase];
    applyCursor = true;
  }

  if (applyCursor) {
    SetCursor(hCursor);
  }

  TControl::HandleCursorHoverSelectionByChildHitTestAndFallback(clickPoint, dispatchArg);
}

// FUNCTION: IMPERIALISM 0x004f6170
void TDiplomacyMapView::RenderDiplomacyLegendSurfaceAndPresent(RECT* presentRect) {
  CTemporaryRegion surface;
  CRect bounds;
  QueryBounds(&bounds);

  if (legendSurfaceModeAt524 != 0) {
    COLORREF savedBackgroundColor = g_pActiveQuickDrawSurfaceContext->blitSurface.backgroundColor;
    COLORREF savedForegroundColor = g_pActiveQuickDrawSurfaceContext->blitSurface.foregroundColor;

    TQuickDrawSurfaceContext* previousSurface = 0;
    int contextFlags = 0;
    GetGWorld(&previousSurface, &contextFlags);
    SetGWorld(g_pPrimaryRenderSurfaceContext, contextFlags);

    if (previousSurface != g_pPrimaryRenderSurfaceContext) {
      LockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
    }

    // The fixed call at 0x4f6216 resolves through the ILT to TPicture::Draw
    // (0x48f3c0). A virtual/self call recursively re-enters this renderer until
    // the thread stack overflows.
    TPicture::Draw(presentRect);

    TCountry** terrainDescriptors = g_apTerrainTypeDescriptorTable;
    short terrainIndex = 0;
    do {
      if (*terrainDescriptors != 0) {
        this->BlitDiplomacyMapEventPaletteMaskToSurface(terrainIndex, terrainIndex + 0x258);
      }
      terrainIndex = static_cast<short>(terrainIndex + 1);
      terrainDescriptors = terrainDescriptors + 1;
    } while (terrainIndex < 7);

    g_pViewMgr->ApplyLegendSplitSlot34(0x3f);

    terrainIndex = 7;
    terrainDescriptors = g_apTerrainTypeDescriptorTable + 7;
    do {
      if (*terrainDescriptors != 0) {
        this->BlitDiplomacyMapEventPaletteMaskToSurface(terrainIndex, 0x2bb);
      }
      terrainIndex = static_cast<short>(terrainIndex + 1);
      terrainDescriptors = terrainDescriptors + 1;
    } while (terrainIndex < 0x17);

    SetQuickDrawFillColor(0);
    DrawNames(presentRect);

    if (previousSurface != g_pPrimaryRenderSurfaceContext) {
      UnlockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
    }

    SetGWorld(previousSurface, contextFlags);
    SetQuickDrawColorAndSyncGlobals(savedForegroundColor);
    SetGlobalBlitTransparentColorRaw(savedBackgroundColor);
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
  RgnHandle frameRegion =
      g_pMacViewMgr->GetClipRegionSlotByIndex(static_cast<short>(frameRegionSelectorAt98));
  QDFrameRgn(frameRegion);
  SetQuickDrawFillColor(0);
}

// FUNCTION: IMPERIALISM 0x004f6440
void TDiplomacyMapView::BuildCombinedTerrainTypeRegionMaskAndDispatch() {
  RgnHandle region = NewRgn();

  short terrainIndex = 0;
  TCountry** terrainDescriptors = g_apTerrainTypeDescriptorTable;
  do {
    if (*terrainDescriptors != 0) {
      RgnHandle frameRegion =
          g_pMacViewMgr->GetClipRegionSlotByIndex(static_cast<short>(terrainIndex));
      UnionRgn(region, frameRegion, region);
    }
    terrainIndex = static_cast<short>(terrainIndex + 1);
    terrainDescriptors = terrainDescriptors + 1;
  } while (terrainIndex < 0x17);

  ForwardMapViewVirtualC4IfPresent(region);
  DisposeRgn(region);
}

// FUNCTION: IMPERIALISM 0x004f64c0
void TDiplomacyMapView::RebuildDiplomacyLegendPaletteMode4AndBlit(int activeNationSlot,
                                                                  const RECT* presentRect) {
  TQuickDrawSurfaceContext* previousSurface = 0;
  CPoint maskOrigin;
  int contextFlags = 0;
  RECT blitRect;
  blitRect.left = presentRect->left;
  blitRect.top = presentRect->top;
  blitRect.right = presentRect->right;
  blitRect.bottom = presentRect->bottom;

  if (legendSurfaceModeAt524 != 4) {
    GetGWorld(&previousSurface, &contextFlags);
    SetGWorld(g_pPrimaryRenderSurfaceContext, contextFlags);
    LockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));

    short nationIndex = 0;
    do {
      int eventCode;
      if (nationIndex == static_cast<short>(activeNationSlot)) {
        eventCode = 0x40;
      } else {
        DiplomacyRelationshipStorage relationship =
            g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(activeNationSlot,
                                                                             nationIndex);
        eventCode = g_aDiplomacyRelationPaletteColorCodes[relationship];
      }

      maskOrigin.x = 0;
      maskOrigin.y = 0;
      QuickDrawPaletteIndex paletteIndex = g_pViewMgr->GetColor(static_cast<short>(eventCode));
      maskRuns[nationIndex].BlitMonochromeMaskBytePatternToSurface(
          &g_pActiveQuickDrawSurfaceContext->blitSurface, static_cast<short>(paletteIndex),
          &maskOrigin, 1);

      int packedColor = g_pViewMgr->GetColor(0x3f);
      packedColorRuns[nationIndex].AppendPackedColorDword(
          g_pActiveQuickDrawSurfaceContext->blitSurface.pixelBits, packedColor);

      nationIndex = static_cast<short>(nationIndex + 1);
    } while (nationIndex < 0x17);

    DrawNames(presentRect);
    legendSurfaceModeAt524 = 4;
    UnlockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
    SetGWorld(previousSurface, contextFlags);
  }

  BlitQuickDrawSurfaces(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect, &blitRect,
                        0);
}

// FUNCTION: IMPERIALISM 0x004f66c0
void DiplomacyMaskBufferRun::BlitMonochromeMaskBytePatternToSurface(TQuickDrawBlitSurface* surface,
                                                                    TUiStyleRef paletteColor,
                                                                    const CPoint* origin,
                                                                    unsigned char flipVertical) {
  unsigned char* maskCursor = maskBytesAt00;
  if (maskCursor == 0) {
    return;
  }

  int rowStride = surface->stride;
  unsigned int row = boundsAt04.top;
  unsigned char* destCursor;
  int rowAdvance;
  if (flipVertical == 0) {
    destCursor = surface->pixelBits + (origin->y + row) * rowStride + origin->x + boundsAt04.left;
    rowAdvance = boundsAt04.left + (rowStride - boundsAt04.right);
  } else {
    int surfaceHeight = surface->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (surfaceHeight < 1) {
      surfaceHeight = -surfaceHeight;
    }
    destCursor = surface->pixelBits + (((surfaceHeight - origin->y) - row) - 1) * rowStride +
                 origin->x + boundsAt04.left;
    rowAdvance = boundsAt04.left + (-rowStride - boundsAt04.right);
  }

  if (static_cast<int>(row) < boundsAt04.bottom) {
    do {
      int x = boundsAt04.left;
      unsigned char* rowCursor = destCursor;
      if (x < boundsAt04.right) {
        do {
          if (*maskCursor == 0) {
            x += 8;
            destCursor = rowCursor + 8;
          } else if (*maskCursor == 0xff) {
            unsigned int fillByte = static_cast<unsigned char>(paletteColor.value);
            unsigned int packedFill =
                fillByte | (fillByte << 8) | (fillByte << 16) | (fillByte << 24);
            memcpy(rowCursor, &packedFill, sizeof(packedFill));
            memcpy(rowCursor + sizeof(packedFill), &packedFill, sizeof(packedFill));
            x += 8;
            destCursor = rowCursor + 8;
          } else {
            int bit = 1;
            destCursor = rowCursor;
            do {
              if ((*maskCursor & static_cast<unsigned char>(bit)) != 0) {
                *destCursor = static_cast<unsigned char>(paletteColor.value);
              }
              bit = bit * 2;
              x += 1;
              destCursor += 1;
            } while (bit < 0x100);
          }
          maskCursor += 1;
          rowCursor = destCursor;
        } while (x < boundsAt04.right);
      }
      row += 1;
      destCursor += rowAdvance;
    } while (static_cast<int>(row) < boundsAt04.bottom);
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
  CPoint maskOrigin;
  int contextFlags = 0;
  RECT blitRect;
  blitRect.left = presentRect->left;
  blitRect.top = presentRect->top;
  blitRect.right = presentRect->right;
  blitRect.bottom = presentRect->bottom;

  if (legendSurfaceModeAt524 != 1) {
    GetGWorld(&previousSurface, &contextFlags);
    SetGWorld(g_pPrimaryRenderSurfaceContext, contextFlags);
    LockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));

    int terrainIndex = 0;
    TCountry** terrainDescriptors = g_apTerrainTypeDescriptorTable;
    do {
      if (*terrainDescriptors != 0) {
        DiplomacyRelationshipNotch relationshipNotch =
            g_pDiplomacyTurnStateManager->GetRelationshipNotch(
                activeNationSlot, static_cast<NationSlot>(terrainIndex));

        maskOrigin.x = 0;
        maskOrigin.y = 0;
        QuickDrawPaletteIndex paletteIndex =
            g_pViewMgr->GetColor(static_cast<short>(relationshipNotch + 200));
        maskRuns[terrainIndex].BlitMonochromeMaskBytePatternToSurface(
            &g_pActiveQuickDrawSurfaceContext->blitSurface, static_cast<short>(paletteIndex),
            &maskOrigin, 1);

        int packedColor = g_pViewMgr->GetColor(0x3f);
        packedColorRuns[terrainIndex].AppendPackedColorDword(
            g_pActiveQuickDrawSurfaceContext->blitSurface.pixelBits, packedColor);
      }
      terrainIndex++;
      terrainDescriptors++;
    } while (terrainIndex < 0x17);

    DrawNames(presentRect);
    legendSurfaceModeAt524 = 1;
    UnlockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
    SetGWorld(previousSurface, contextFlags);
  }

  BlitQuickDrawSurfaces(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect, &blitRect,
                        0);
  (void)presentRect;
}

// FUNCTION: IMPERIALISM 0x004f6b10
void TDiplomacyMapView::BuildTurnEventMonochromeMaskBuffers(int maskIndex, int eventCode) {
  CPoint maskOrigin;
  maskOrigin.x = 0;
  maskOrigin.y = 0;
  QuickDrawPaletteIndex paletteIndex = g_pViewMgr->GetColor(static_cast<short>(eventCode));
  DiplomacyMaskBufferRun* maskRun = &maskRuns[maskIndex];
  maskRun->BlitMonochromeMaskBytePatternToSurface(&g_pActiveQuickDrawSurfaceContext->blitSurface,
                                                  static_cast<short>(paletteIndex), &maskOrigin, 1);

  int packedColor = g_pViewMgr->GetColor(0x3f);
  StrategicMapCallbackRecord* packedRun = &packedColorRuns[maskIndex];
  packedRun->AppendPackedColorDword(g_pActiveQuickDrawSurfaceContext->blitSurface.pixelBits,
                                    packedColor);
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
    int srcRowAdvance =
        (((srcRowWidth + 3) & 0xfffffffc) - maskRun->boundsAt04.right) + maskRun->boundsAt04.left;
    int surfaceHeight = surface->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (surfaceHeight < 1) {
      surfaceHeight = -surfaceHeight;
    }
    int row = maskRun->boundsAt04.top;
    int rowStride = surface->blitSurface.stride;
    unsigned char* destCursor = surface->blitSurface.pixelBits +
                                ((surfaceHeight - row) - 1) * rowStride + maskRun->boundsAt04.left;
    int destRowAdvance = (maskRun->boundsAt04.left - maskRun->boundsAt04.right) - rowStride;
    unsigned char* srcCursor = static_cast<unsigned char*>(bmpHandle->m_dibBits);

    if (row < maskRun->boundsAt04.bottom) {
      do {
        int x = maskRun->boundsAt04.left;
        if (x < maskRun->boundsAt04.right) {
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
          } while (x < maskRun->boundsAt04.right);
        }
        row += 1;
        srcCursor += srcRowAdvance;
        destCursor += destRowAdvance;
      } while (row < maskRun->boundsAt04.bottom);
    }
  }

  g_pModuleLibraryCacheState->ReleaseRecordByHandle(bmpHandle);
  int packedColor = g_pViewMgr->GetColor(0x3f);
  StrategicMapCallbackRecord* packedRun = &packedColorRuns[maskIndex];
  packedRun->AppendPackedColorDword(surface->GetBlitSurface()->pixelBits, packedColor);
}

// Selects a minister action topic: repositions the old/new topic buttons via
// Locate, toggles the 'ltab'/'rtab' bracket TPicture controls around the new
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

  CPoint layoutPosition(0x39, 0x320);
  actionButtonsA0[stateFlagAtB8]->Locate(layoutPosition, 1);
  layoutPosition.y = 0x162;
  actionButtonsA0[newTopic]->Locate(layoutPosition, 1);

  TPicture* ltabControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagLtab));
  ltabControl->AssertValid();
  TPicture* rtabControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagRtab));
  rtabControl->AssertValid();

  if (newTopic == 0 || newTopic == 4) {
    ltabControl->Show(1, 1);
    rtabControl->Show(0, 1);
    if (newTopic == 0) {
      ltabControl->SetPictureResourceIdAndRefresh(0x1389, 1);
    } else {
      ltabControl->SetPictureResourceIdAndRefresh(0x138a, 1);
    }
  } else {
    ltabControl->Show(0, 1);
    rtabControl->Show(1, 1);
    if (g_pSimMgr->mode == 6) {
      rtabControl->SetPictureResourceIdAndRefresh(0x20da, 1);
    } else {
      rtabControl->SetPictureResourceIdAndRefresh(static_cast<short>(newTopic + 0x138a), 1);
    }
  }

  this->ForceRedraw();
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
  // TrackMouse at the same vtable byte offset.
  static_cast<TPanelView*>(actionButtonsA0[newTopic])->Setup();

  if (selectedTerrainIndexAt90 != frameRegionSelectorAt98) {
    frameRegionSelectorAt98 = selectedTerrainIndexAt90;
    legendSurfaceModeAt524 = 6;
  }

  InvalidateCityDialogRectRegion(&mapViewportRect514, 1);
}

// FUNCTION: IMPERIALISM 0x004f7040
char TDiplomacyMapView::PoseWarOffer(short sourceNationSlot, int minorNationSlot,
                                     int enemyNationSlot, int promptCode) {
  ChangeSelectedActionTopic(5);
  return static_cast<TOffersPanelView*>(actionButtonsA0[5])
      ->PoseWarOffer(sourceNationSlot, minorNationSlot, enemyNationSlot, promptCode);
}

// FUNCTION: IMPERIALISM 0x004f7080
void TDiplomacyMapView::PoseOffer(short sourceNation, short targetNation, short offerType) {
  ChangeSelectedActionTopic(5);
  static_cast<TOffersPanelView*>(actionButtonsA0[5])
      ->PoseOffer(sourceNation, targetNation, offerType);
}

// FUNCTION: IMPERIALISM 0x004f70c0
void TDiplomacyMapView::DoEvent(int commandId, TEventHandler* panelEvent, TEvent* extra) {
  if (commandId == 0x14) {
    int tabIndex = 0;
    const unsigned int* tagTable = g_aDiplomacyActionTopicTabTags;
    do {
      if (static_cast<unsigned int>(panelEvent->controlTag) == *tagTable) {
        break;
      }
      tagTable += 1;
      tabIndex += 1;
    } while (tagTable < g_aDiplomacyActionTopicTabTags + 6);
    if (tabIndex < 6) {
      ChangeSelectedActionTopic(tabIndex);
      return;
    }
  } else {
    TControl::DoEvent(commandId, panelEvent, extra);
  }
}

// FUNCTION: IMPERIALISM 0x004f7130
void TDiplomacyMapView::DoKeyEvent(TToolboxEvent* event) {
  if (stateFlagAtB8 == 5) {
    actionButtonsA0[5]->DoKeyEvent(event);
    return;
  }
  // Non-virtual call to TEventHandler::DoKeyEvent's body (orig routes through the
  // ILT thunk at 0x401d61 -> 0x48a380); the qualified call forces static dispatch.
  TEventHandler::DoKeyEvent(event);
}

// FUNCTION: IMPERIALISM 0x004f7170
void TDiplomacyMapView::SetOverlay(int overlay) {
  interactionModeAt94 = overlay;
  InvalidateCityDialogRectRegion(&mapViewportRect514, 1);
}

// FUNCTION: IMPERIALISM 0x004f71a0
void TDiplomacyMapView::DrawVoteNuggets() {
  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithDefaultFallback(0x10);

  short selectedTier = visibleVoteTier528;
  int policyIndex = 0;
  do {
    short tierValue = g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix[policyIndex];
    int iconCode = g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix[policyIndex];
    if (tileHasOwnerFlags52C[policyIndex] && iconCode != -1 && tierValue <= selectedTier) {
      RECT* iconRect = &tileMarkerRects6AC[policyIndex];
      short iconX = g_pGlobalMapState->GetMapImprovementTierBucketOffset(iconCode);

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

      CDib* activeDib = g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib;
      if (activeDib != 0) {
        int surfaceHeight = activeDib->m_pInfoHeader->bmiHeader.biHeight;
        if (surfaceHeight < 1) {
          surfaceHeight = -surfaceHeight;
        }
        OffsetRect(&destRect, 0, (surfaceHeight - destRect.top) - destRect.bottom);
      }

      BlitQuickDrawSurfaces(g_pMacViewMgr->atlas6b8->GetBlitSurface(),
                            g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect, &destRect,
                            0x24);

      destRect.left = iconRect->left - 1;
      destRect.top = iconRect->top - 1;
      destRect.right = iconRect->right + 1;
      destRect.bottom = iconRect->bottom + 1;
      if (tierValue == selectedTier) {
        g_pViewMgr->ApplyLegendSplitSlot34(6);
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

// Presents the "diplomacy action rejected" modal: resolves the rejection-reason string for the
// current proposal mode (GetString group 0x2754, index proposalArrayMode - 1) and shows it.
// FUNCTION: IMPERIALISM 0x004f7400
void ShowDiplomacyActionRejectedNotice() {
  CString message;
  g_pSimMgr->GetString(0x2754, g_pDiplomacyTurnStateManager->proposalArrayMode - 1, &message);
  g_pViewMgr->ModalMessage(3, CString(g_szEmptyString), message, g_ptDiplomacyNoticeModalMessage, 0,
                           0);
}

// FUNCTION: IMPERIALISM 0x004f74f0
char TDiplomacyMapView::CheckEntanglements(int targetNationSlot, eDipAction action) {
  if (g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(targetNationSlot,
                                                                  selectedTerrainIndexAt90) != 0) {
    CString formattedIntro;
    CString entangledNations;
    CString unusedSuffix;
    CString templateText;
    CString targetName;
    CString title;

    g_apTerrainTypeDescriptorTable[targetNationSlot]->FormatOverlayTerrainLabelText(&targetName);
    int introStringIndex = 0;
    if (action != kDipActionAlliance) {
      introStringIndex = 4;
    }
    g_pSimMgr->GetString(0x275d, introStringIndex, &templateText);
    scanBracketExpressions(g_pSimMgr, &formattedIntro, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(targetName));

    entangledNations = CString(g_pDiplomacyPanelEmptyText_00654ec8);
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(static_cast<short>(targetNationSlot),
                                                          static_cast<short>(nationSlot)) != 0) {
        CString nationName;
        g_apTerrainTypeDescriptorTable[nationSlot]->FormatOverlayTerrainLabelText(&nationName);
        entangledNations += "   " + nationName + "\n";
      }
    }

    templateText = formattedIntro + "\n" + entangledNations + unusedSuffix;
    g_pSimMgr->GetString(0x275d, 5, &title);
    return g_pViewMgr->ModalMessage(3, title, templateText, g_ptDiplomacyNoticeModalMessage, 0, 0);
  }
  return 1;
}

#ifdef IMPERIALISM_RUNTIME_TESTS
void TDiplomacyMapView::ActivateNation(short nationSlot) {
  if (nationSlot < 0 || nationSlot >= kNationSlotCount ||
      g_apTerrainTypeDescriptorTable[nationSlot] == 0) {
    return;
  }
  g_runtimeSemanticDiplomacyNation = nationSlot;
  CPoint ignoredPoint(0, 0);
  CPoint ignoredOrigin(0, 0);
  DoMouseCommand(ignoredPoint, 0, ignoredOrigin);
  g_runtimeSemanticDiplomacyNation = -1;
}

short TDiplomacyMapView::RuntimeActiveNation() const {
  return activeNationC2;
}

short TDiplomacyMapView::RuntimeRelationshipOverlaySourceNation() const {
  if (interactionModeAt94 != 1) {
    return -1;
  }
  return frameRegionSelectorAt98;
}

int TDiplomacyMapView::RuntimeActionTopicIndex() const {
  return stateFlagAtB8;
}

short TDiplomacyMapView::RuntimeDrawPolicyIconForNation(short nationSlot) {
  if (nationSlot < 0 || nationSlot >= kNationSlotCount) {
    return -1;
  }

  TQuickDrawSurfaceContext* previousSurface;
  int contextFlags;
  GetGWorld(&previousSurface, &contextFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, contextFlags);
  g_runtimePolicyIconOffsetByNation[nationSlot] = -1;
  RECT nationRect = nationTextHitRectsC4[nationSlot];
  DrawIcons(&nationRect);
  SetGWorld(previousSurface, contextFlags);
  return g_runtimePolicyIconOffsetByNation[nationSlot];
}
#endif

// 0x005DA040 and 0x005DA180 moved to TViewMgr::RefreshMainDialogAndCursorHelp
// / ShowDealBookScreen (src/game/ui_core/TViewMgr.cpp): the vtable
// evidence (`just vtable TViewMgr`) shows both are TViewMgr's own vtable slots 0x60/0x64, not
// TDiplomacyMapView methods -- neither body ever reads `this`, and this class's prior
// attribution called TView::SetHoverHelpText with an implicit (wrong) `this` receiver
// instead of the real disassembly's explicitly-resolved 'main' control.
