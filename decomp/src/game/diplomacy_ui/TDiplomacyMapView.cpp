// TDiplomacyMapView QuickDraw legend rendering slice.

#include "game/nation_domain_types.h"
#include "game/map_domain_types.h"
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
#include "game/gfx/TResourceMgr.h"
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

class ScopedDefaultDibPaletteSelection {
public:
  explicit ScopedDefaultDibPaletteSelection(CDC* dc) : m_dc(dc), m_previousPalette(NULL) {
    if (m_dc != NULL) {
      m_previousPalette = m_dc->SelectPalette(g_pResourceMgr->EnsureDefaultDibPalette(), FALSE);
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
  delete[] maskBytes;
}

// Clamps `rect` inside `bounds`, preserving the rect's width/height.

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

static inline void AssertActionButtonResolved(void* button) {
  if (button == NULL) {
    FailNilPointerWithAssert(s_SourcePathUDiplomacyViews, 0x3a7);
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

IMPLEMENT_DYNCREATE(TDiplomacyMapView, TPicture)

// FUNCTION: IMPERIALISM 0x004f3b80
TDiplomacyMapView::TDiplomacyMapView() : TPicture() {
  interactionMode = 0;
  frameRegionSelector = 0;
  selectedTerrainIndex = 0;
  region = 0;
  legendSurfaceMode = 6;
  stateFlag = 0;
  g_pAmbitApplication->cursorRegionInvalid = TRUE;
}

// FUNCTION: IMPERIALISM 0x004f3c70
DiplomacyMaskBufferRun::DiplomacyMaskBufferRun() {
  maskBytes = 0;
}

// FUNCTION: IMPERIALISM 0x004f3d60
void TDiplomacyMapView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  BuildDiplomacyNationOverlayGeometryAndHitMasks();
  InitializeDiplomacyMinisterActionControlsAndLabels();
  SetControlHoverHelpText(CString(g_szEmptyString), this);

  if (g_pSimMgr->mode == kGamePhaseDiplomacy) {
    TView* endControl = ResolveControlByTag(kControlTagEnd);
    if (endControl != NULL) {
      endControl->Free();
    }
    TView* querControl = ResolveControlByTag(kControlTagQuer);
    if (querControl != NULL) {
      querControl->Free();
    }
    TView* topBControl = ResolveControlByTag(kControlTagTopB);
    if (topBControl != NULL) {
      topBControl->Free();
    }
    SetPictureRsrcID(0x20d0, 1);
  }
}

// FUNCTION: IMPERIALISM 0x004f3e30
void TDiplomacyMapView::Close() {
  g_pAmbitApplication->cursorRegionInvalid = FALSE;
  TView::Close();
}

// FUNCTION: IMPERIALISM 0x004f3e60
void TDiplomacyMapView::Free() {
  if (region != 0) {
    DisposeRgn(region);
  }
  region = 0;
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x004f3ea0
void TDiplomacyMapView::BuildDiplomacyNationOverlayGeometryAndHitMasks() {
  short labelWidths[23];
  short labelXs[23];
  short labelYs[23];
  memset(labelWidths, 0, sizeof(labelWidths));
  memset(labelXs, 0, sizeof(labelXs));
  memset(labelYs, 0, sizeof(labelYs));

  region = NewRgn();
  for (short terrain = 0; terrain < 0x17; ++terrain) {
    if (g_apTerrainTypeDescriptorTable[terrain] != 0) {
      UnionRgn(region, g_pMacViewMgr->GetCountryRegion(terrain), region);
    }
  }

  mapViewportRect.left = 0x31;
  mapViewportRect.top = 0x2d;
  mapViewportRect.right = 0x24d;
  mapViewportRect.bottom = 0x159;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b68);

  for (short nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    DiplomacyMaskBufferRun* run = &maskRuns[nationIndex];
    RgnHandle nationRgn = g_pMacViewMgr->GetCountryRegion(nationIndex);
    (*nationRgn)->RefreshBoundingBox();
    CopyRect(&run->bounds, &(*nationRgn)->rgnBBox);
    run->bounds.right = run->bounds.left + (((run->bounds.right - run->bounds.left) + 7) >> 3) * 8;
    delete[] run->maskBytes;
    run->maskBytes = new unsigned char[(run->bounds.right - run->bounds.left) *
                                       (run->bounds.bottom - run->bounds.top)];
    unsigned char* mask = run->maskBytes;
    for (int y = run->bounds.top; y < run->bounds.bottom; ++y) {
      for (int x = run->bounds.left; x < run->bounds.right;) {
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
      if (EmptyRgn(g_pMacViewMgr->GetCountryRegion(nationIndex)) == 0) {
        short anchorTile = nation->GetOrComputeOverlayAnchorTileIndex();
        int labelCenterX = (anchorTile % kStrategicMapColumns) * 5 + 0x31;
        int labelY = (anchorTile / kStrategicMapColumns + 9) * 5;
        nation->GetName(&nationName);
        short textWidth = MeasureTextExtentWithCachedQuickDrawStyle(&nationName);
        labelY -= 6;
        labelWidths[nationIndex] = textWidth;
        short labelX = static_cast<short>(labelCenterX) - textWidth / 2;

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
        RECT* labelRect = &nationLabelRects[nationIndex];
        labelRect->left = labelX;
        labelRect->top = labelY;
        labelRect->right = labelX + textWidth;
        labelRect->bottom = labelY + 0xc;
        ClampRectWithinBoundsPreservingSize(labelRect, &mapViewportRect);

        CPoint labelProbe(labelCenterX, (anchorTile / kStrategicMapColumns + 9) * 5 + 8);
        RECT* hitRect = &nationTextHitRects[nationIndex];
        hitRect->left = labelCenterX - 8;
        hitRect->right = labelCenterX + 8;
        if (PtInRgn(&labelProbe, nationRgn) != 0) {
          hitRect->top = labelProbe.y;
          hitRect->bottom = labelProbe.y + 0x10;
        } else {
          hitRect->top = labelProbe.y - 0x20;
          hitRect->bottom = labelProbe.y - 0x10;
        }
        ClampRectWithinBoundsPreservingSize(hitRect, &mapViewportRect);

        int markerX = (static_cast<short>(nation->homeTileIndex) % kStrategicMapColumns) * 5;
        int markerY = (static_cast<short>(nation->homeTileIndex) / kStrategicMapColumns + 9) * 5;
        RECT* anchorRect = &nationAnchorRects[nationIndex];
        anchorRect->left = markerX + 0x29;
        anchorRect->top = markerY - 8;
        anchorRect->right = markerX + 0x39;
        anchorRect->bottom = markerY + 8;
        continue;
      }
    }
    RECT* labelRect = &nationLabelRects[nationIndex];
    labelRect->left = 0;
    labelRect->top = 0;
    labelRect->right = 0;
    labelRect->bottom = 0;
    RECT* hitRect = &nationTextHitRects[nationIndex];
    hitRect->left = 0;
    hitRect->top = 0;
    hitRect->right = 0;
    hitRect->bottom = 0;
  }

  for (int tile = 0; tile < kProvinceCount; ++tile) {
    tileHasOwnerFlags[tile] = g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix[tile] != -1;
    short colX2;
    unsigned short row;
    SplitTileIndexToHexRasterColumnX2AndRow(g_pGlobalMapState->cityScoreTable[tile].cityTileIndex,
                                            &colX2, &row);
    RECT* tileRect = &tileMarkerRects[tile];
    tileRect->left = (colX2 * 5) / 2 - 4 + mapViewportRect.left;
    tileRect->top = static_cast<short>(row) * 5 - 3 + mapViewportRect.top;
    tileRect->right = tileRect->left + 9;
    tileRect->bottom = tileRect->top + 6;
  }

  short activeNation = g_pSimMgr->GetPlayerCountry();
  selectedTerrainIndex = activeNation;
  frameRegionSelector = activeNation;
  this->activeNation = activeNation;
  actionCode = kDipActionInspectNation;
}

// FUNCTION: IMPERIALISM 0x004f4620
void TDiplomacyMapView::InitializeDiplomacyMinisterActionControlsAndLabels() {
  CString text;

  for (int buttonIndex = 0; buttonIndex < 6; ++buttonIndex) {
    TView* button = ResolveControlByTag(g_diplomacyActionButtonTagTable[buttonIndex]);
    actionButtons[buttonIndex] = button;
    AssertActionButtonResolved(button);
  }

  TInfoPanelView* infoActionButton = static_cast<TInfoPanelView*>(actionButtons[0]);
  infoActionButton->SetInfoCountry(activeNation);
  infoActionButton->Setup();

  for (short i = 0; i < 6; ++i) {
    TView* hoverControl = ResolveControlByTag(g_aDiplomacyActionTopicTabTags[i]);
    g_pSimMgr->GetString(0x2733, static_cast<short>(i + 0x52), &text);
    SetControlHoverHelpText(text, hoverControl);
  }

  if (g_pSimMgr->mode == kGamePhaseDiplomacy) {
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
    offrControl->Locate(g_diplomacyPopupOffscreenPosition, false);
  }
}

// FUNCTION: IMPERIALISM 0x004f48c0
void TDiplomacyMapView::Draw(RECT* rectBuffer) {
  CString unusedScratch;

  if (interactionMode == 1) {
    RebuildDiplomacyLegendPaletteMode1AndBlit(frameRegionSelector, rectBuffer);
  } else if (interactionMode == 2) {
    RenderDiplomacyLegendSurfaceAndPresent(rectBuffer);
  } else if (interactionMode == 4) {
    RebuildDiplomacyLegendPaletteMode4AndBlit(frameRegionSelector, rectBuffer);
  } else {
    RenderDiplomacyLegendSurfaceAndPresent(rectBuffer);
  }

  SetQuickDrawFillColor(0xffffff);
  RgnHandle frameRegion = g_pMacViewMgr->GetCountryRegion(static_cast<short>(frameRegionSelector));
  QDFrameRgn(frameRegion);
  SetQuickDrawFillColor(0);

  if (interactionMode == 5) {
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

  for (int gp = 0; gp < 7; ++gp) {
    TCountry* terrain = g_apTerrainTypeDescriptorTable[gp];
    if (terrain == NULL) {
      continue;
    }
    RECT* labelRect = &nationLabelRects[gp];
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
      terrain->GetName(&label);
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
    if (terrain == NULL) {
      continue;
    }
    RECT* labelRect = &nationLabelRects[mn];
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
      terrain->GetName(&label);
      ResolveUiThemeColor(0x2b67, &styleForeground);
      ResolveUiThemeColor(0x2b6f, &styleShadow);
    } else {
      int band;
      if (code >= 200) {
        band = code - 200;
      } else if (code >= 100) {
        band = code - 100;
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

  if (interactionMode != 1 && interactionMode != 4 && interactionMode != 2) {
    return;
  }

  RECT presentRectCopy = *presentRect;
  for (short terrainIndex = 0; terrainIndex < 0x17; ++terrainIndex) {
    if (g_apTerrainTypeDescriptorTable[terrainIndex] == 0) {
      continue;
    }

    RECT* hitRect = &nationTextHitRects[terrainIndex];
    RECT intersection;
    if (SectRect(&presentRectCopy, hitRect, &intersection) == 0) {
      continue;
    }

    bool boycottFlag = false;
    bool offsetOverlayX = false;
    short iconOffset = -1;

    short compatValue =
        g_pDiplomacyTurnStateManager->GetEmbassyStatus(frameRegionSelector, terrainIndex);
    if (compatValue != 0) {
      short compatIconX = static_cast<short>((compatValue + 0x16) * 0x10);
      RECT compatSrcRect = {compatIconX, 0, static_cast<int>(compatIconX + 0x10), 0x10};
      UpdatePaletteIndexWithDefaultFallback(0x10);
      SetQuickDrawFillColor(0);
      BlitRectWithOptionalTransparency(g_pMacViewMgr->tileOverlayStripWorlds[2]->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &compatSrcRect, &nationAnchorRects[terrainIndex], 0x24, 0);
      UpdatePaletteIndexWithDefaultFallback(0x13);
    }

    if (interactionMode == 4) {
      if (g_pDiplomacyTurnStateManager->IsGreatPower(frameRegionSelector)) {
        short need = g_apNationStates[frameRegionSelector]->diplomacyPolicyByNation[terrainIndex];
        if (need == 0x133) {
          iconOffset = 0x150;
        } else if (need == 0x134) {
          iconOffset = 0x160;
        } else if (need != -1) {
          iconOffset =
              static_cast<short>(policyIconColumns[need - kDiplomacyProposalJoinEmpire] << 4);
        }
      }
    } else if (interactionMode == 2) {
      short relation =
          g_apTerrainTypeDescriptorTable[frameRegionSelector]->needLevelByNation[terrainIndex];
      boycottFlag = (frameRegionSelector < 7) &&
                    (g_apNationStates[frameRegionSelector]->colonyBoycottFlags[terrainIndex] != 0);
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
    } else { // interactionMode == 1
      if (g_pDiplomacyTurnStateManager->IsGreatPower(frameRegionSelector)) {
        short need = g_apNationStates[frameRegionSelector]->diplomacyGrantByNation[terrainIndex];
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
      BlitRectWithOptionalTransparency(g_pMacViewMgr->tileOverlayStripWorlds[2]->GetBlitSurface(),
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
      BlitRectWithOptionalTransparency(g_pMacViewMgr->tileOverlayStripWorlds[2]->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &boycottSrcRect, &boycottDstRect, 0x24, 0);
      UpdatePaletteIndexWithDefaultFallback(0x13);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004f5410
void TDiplomacyMapView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {

  CRect invalidRect;
  CRect recurringGrantRect;
  bool grantUpdated;
  bool policyUpdated;
  bool rejectAction = false;
  bool clearAction = false;
  bool refreshToolbar = false;
  eDipAction action = ResolveDiplomacyActionFromClickAndUpdateTarget(&point);

  switch (action) {
  case kDipActionJoinEmpire: {
    if (g_apNationStates[selectedTerrainIndex]->diplomacyPolicyByNation[activeNation] ==
        kDiplomacyProposalJoinEmpire) {
      g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(activeNation, -1);
      break;
    }
    if (!g_pDiplomacyTurnStateManager->IsActionAllowed(selectedTerrainIndex, activeNation,
                                                       action)) {
      rejectAction = true;
      break;
    }
    if (!CheckEntanglements(activeNation, action)) {
      clearAction = true;
      break;
    }
    g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(activeNation,
                                                                 kDiplomacyProposalJoinEmpire);
    break;
  }
  case kDipActionAlliance: {
    if (g_apNationStates[selectedTerrainIndex]->diplomacyPolicyByNation[activeNation] ==
        kDiplomacyProposalAlliance) {
      g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(activeNation, -1);
      break;
    }
    if (!g_pDiplomacyTurnStateManager->IsActionAllowed(selectedTerrainIndex, activeNation,
                                                       action)) {
      rejectAction = true;
      break;
    }
    if (!CheckEntanglements(activeNation, action)) {
      clearAction = true;
      break;
    }
    g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(activeNation,
                                                                 kDiplomacyProposalAlliance);
    break;
  }
  case kDipActionNonAggressionPact: {
    if (g_apNationStates[selectedTerrainIndex]->diplomacyPolicyByNation[activeNation] ==
        kDiplomacyProposalNonAggressionPact) {
      g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(activeNation, -1);
      break;
    }
    if (!g_pDiplomacyTurnStateManager->IsActionAllowed(selectedTerrainIndex, activeNation,
                                                       action)) {
      rejectAction = true;
      break;
    }
    g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(
        activeNation, kDiplomacyProposalNonAggressionPact);
    break;
  }
  case kDipActionPeaceTreaty: {
    if (g_apNationStates[selectedTerrainIndex]->diplomacyPolicyByNation[activeNation] ==
        kDiplomacyProposalPeaceTreaty) {
      g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(activeNation, -1);
      break;
    }
    if (!g_pDiplomacyTurnStateManager->IsActionAllowed(selectedTerrainIndex, activeNation,
                                                       action)) {
      rejectAction = true;
      break;
    }
    g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(activeNation,
                                                                 kDiplomacyProposalPeaceTreaty);
    break;
  }
  case kDipActionDeclareWar: {
    if (g_apNationStates[selectedTerrainIndex]->diplomacyPolicyByNation[activeNation] ==
        kDiplomacyProposalDeclareWar) {
      g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(activeNation, -1);
      break;
    }
    if (!g_pDiplomacyTurnStateManager->IsActionAllowed(selectedTerrainIndex, activeNation,
                                                       action)) {
      rejectAction = true;
      break;
    }
    g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(activeNation,
                                                                 kDiplomacyProposalDeclareWar);
    break;
  }
  case kDipActionOneTimeGrant: {
    if (g_apNationStates[selectedTerrainIndex]->diplomacyGrantByNation[activeNation] ==
        g_awDiplomacyGrantValueTable[selectedGrantRow]) {
      grantUpdated =
          g_apNationStates[selectedTerrainIndex]->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(
              activeNation, -1);
    } else {
      if (!g_pDiplomacyTurnStateManager->IsActionAllowed(selectedTerrainIndex, activeNation,
                                                         action)) {
        rejectAction = true;
        break;
      }
      grantUpdated =
          g_apNationStates[selectedTerrainIndex]->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(
              activeNation, g_awDiplomacyGrantValueTable[selectedGrantRow]);
      if (!grantUpdated) {
        g_pDiplomacyTurnStateManager->proposalArrayMode = 0x17;
        rejectAction = true;
        break;
      }
    }
    if (!grantUpdated) {
      break;
    }
    invalidRect.left = 0x32;
    invalidRect.top = 0x17c;
    invalidRect.right = 0xe6;
    invalidRect.bottom = 0x190;
    InvalidateCityDialogRectRegion(&invalidRect, 1);
    refreshToolbar = true;
    break;
  }
  case kDipActionRecurringGrant: {
    short grantValue = static_cast<short>(g_awDiplomacyGrantValueTable[selectedGrantRow] | 0x4000);
    if (g_apNationStates[selectedTerrainIndex]->diplomacyGrantByNation[activeNation] ==
        grantValue) {
      grantUpdated =
          g_apNationStates[selectedTerrainIndex]->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(
              activeNation, -1);
    } else {
      if (!g_pDiplomacyTurnStateManager->IsActionAllowed(selectedTerrainIndex, activeNation,
                                                         action)) {
        rejectAction = true;
        break;
      }
      grantUpdated =
          g_apNationStates[selectedTerrainIndex]->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(
              activeNation, grantValue);
      if (!grantUpdated) {
        g_pDiplomacyTurnStateManager->proposalArrayMode = 0x17;
        rejectAction = true;
        break;
      }
    }
    if (!grantUpdated) {
      break;
    }
    recurringGrantRect.left = 0x32;
    recurringGrantRect.top = 0x17c;
    recurringGrantRect.right = 0xe6;
    recurringGrantRect.bottom = 0x190;
    InvalidateCityDialogRectRegion(&recurringGrantRect, 1);
    refreshToolbar = true;
    break;
  }
  case kDipActionTradeSubsidy:
  case kDipActionTradePolicy:
  case kDipActionBoycott: {
    if (!g_pDiplomacyTurnStateManager->IsActionAllowed(selectedTerrainIndex, activeNation,
                                                       action)) {
      rejectAction = true;
      break;
    }

    if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) == 0 || activeNation < kMajorNationCount) {
      short policyValue = g_awDiplomacyTradePolicyIconValueTable[selectedGrantRow];
      if (g_apNationStates[selectedTerrainIndex]->needLevelByNation[activeNation] == policyValue) {
        g_apNationStates[selectedTerrainIndex]->SetTradePolicyTo(activeNation, 100);
      } else {
        g_apNationStates[selectedTerrainIndex]->SetTradePolicyTo(activeNation, policyValue);
      }
    } else {
      g_apNationStates[selectedTerrainIndex]->SetTradePolicyTo(activeNation, 100);
      for (int policyIndex = 0; policyIndex < 6; ++policyIndex) {
        if (g_pDiplomacyTurnStateManager->GetFavoriteTradePartner(activeNation) ==
            selectedTerrainIndex) {
          break;
        }
        g_apNationStates[selectedTerrainIndex]->SetTradePolicyTo(
            activeNation, g_awDiplomacyTradePolicyIconValueTable[policyIndex]);
      }
    }
    break;
  }
  case kDipActionInspectNation: {
    if (frameRegionSelector != activeNation) {
      frameRegionSelector = activeNation;
      static_cast<TInfoPanelView*>(actionButtons[0])->SetInfoCountry(activeNation);
      static_cast<TInfoPanelView*>(actionButtons[0])->Setup();
      legendSurfaceMode = 6;
      InvalidateCityDialogRectRegion(&mapViewportRect, 1);
    }
    break;
  }
  case kDipActionBuildEmbassy: {
    if (g_apNationStates[selectedTerrainIndex]->diplomacyPolicyByNation[activeNation] ==
        kDiplomacyProposalBuildEmbassy) {
      policyUpdated =
          g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(activeNation, -1);
    } else {
      if (!g_pDiplomacyTurnStateManager->IsActionAllowed(selectedTerrainIndex, activeNation,
                                                         action)) {
        rejectAction = true;
        break;
      }
      policyUpdated = g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(
          activeNation, kDiplomacyProposalBuildEmbassy);
    }
    refreshToolbar = policyUpdated;
    break;
  }
  case kDipActionBuildConsulate: {
    if (g_apNationStates[selectedTerrainIndex]->diplomacyPolicyByNation[activeNation] ==
        kDiplomacyProposalBuildConsulate) {
      policyUpdated =
          g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(activeNation, -1);
    } else {
      if (!g_pDiplomacyTurnStateManager->IsActionAllowed(selectedTerrainIndex, activeNation,
                                                         action)) {
        rejectAction = true;
        break;
      }
      policyUpdated = g_apNationStates[selectedTerrainIndex]->SetDiplomacyPolicyTo(
          activeNation, kDiplomacyProposalBuildConsulate);
    }
    refreshToolbar = policyUpdated;
    break;
  }
  case kDipActionLinkTradePolicy: {
    TCountry* targetNation = g_apTerrainTypeDescriptorTable[activeNation];
    short controllingNation = targetNation->encodedNationSlot;
    if (controllingNation >= 200) {
      controllingNation = static_cast<short>(controllingNation - 200);
    } else if (controllingNation >= 100) {
      controllingNation = static_cast<short>(controllingNation - 100);
    } else {
      controllingNation = targetNation->nationSlot;
    }
    if (controllingNation != selectedTerrainIndex) {
      TGreatPower* sourceNation = g_apNationStates[selectedTerrainIndex];
      sourceNation->SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(
          activeNation, sourceNation->colonyBoycottFlags[activeNation] == 0);
    }
    break;
  }
  default:
    break;
  }

  if (rejectAction) {
    ShowDiplomacyActionRejectedNotice();
  }
  if (rejectAction || clearAction) {
    action = kDipActionNone;
  }
  if (refreshToolbar) {
    TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(ResolveControlByTag(kControlTagTool));
    toolbar->AssertValid();
    toolbar->UpdateControlTagTreaTextFromNationAndMapContext(g_pSimMgr->GetPlayerCountry());
  }
  if (action != kDipActionNone && activeNation != -1) {
    invalidRect = nationTextHitRects[activeNation];
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
    activeNation = static_cast<short>(terrainIndex);
    if (actionCode != kDipActionInspectNation && terrainIndex == selectedTerrainIndex) {
      return kDipActionSelectedNation;
    }
    return actionCode;
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
  if (interactionMode == 5) {
    return kDipActionNone;
  }

  CPoint localPoint = this->ViewToQDPt(clickPoint);

  int terrainIndex = 0;
  do {
    if (g_apTerrainTypeDescriptorTable[terrainIndex] != 0) {
      char hit = g_pMacViewMgr->PtInCountry(&localPoint, static_cast<short>(terrainIndex));
      if (hit != 0) {
        break;
      }
    }
    terrainIndex += 1;
  } while (terrainIndex < kNationSlotCount);

  eDipAction action = kDipActionNone;
  if (terrainIndex < kNationSlotCount) {
    action = actionCode;
    activeNation = static_cast<short>(terrainIndex);
    if (action != kDipActionInspectNation && terrainIndex == selectedTerrainIndex) {
      return kDipActionSelectedNation;
    }
  } else {
    activeNation = -1;
  }
  return action;
}

// FUNCTION: IMPERIALISM 0x004f5f90
void TDiplomacyMapView::DoSetCursor(CPoint* point, RgnHandle hitArg) {}

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
      char regionHit = g_pMacViewMgr->PtInCountry(&localPoint, static_cast<short>(hitIndex));
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
        g_pDiplomacyTurnStateManager->IsActionAllowed(selectedTerrainIndex, activeNation, action);

    short cursorId;
    if (!valid) {
      cursorId = 0x41b;
    } else {
      cursorId = cursorIdsByAction[action];
      if (action == kDipActionTradeSubsidy || action == kDipActionOneTimeGrant ||
          action == kDipActionRecurringGrant) {
        cursorId = static_cast<short>(cursorId + selectedGrantRow);
      }
    }
    currentCursorResourceId = cursorId;
    hCursor = g_pViewMgr->turnEventCursors[cursorId - TViewMgr::kCursorResourceIdBase];
    applyCursor = true;
  } else if (currentCursorResourceId != 0x41b) {
    currentCursorResourceId = 0x41b;
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

  if (legendSurfaceMode != 0) {
    COLORREF savedBackgroundColor = g_pActiveQuickDrawSurfaceContext->blitSurface.backgroundColor;
    COLORREF savedForegroundColor = g_pActiveQuickDrawSurfaceContext->blitSurface.foregroundColor;

    TQuickDrawSurfaceContext* previousSurface = 0;
    int contextFlags = 0;
    GetGWorld(&previousSurface, &contextFlags);
    SetGWorld(g_pPrimaryRenderSurfaceContext, contextFlags);

    if (previousSurface != g_pPrimaryRenderSurfaceContext) {
      LockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
    }

    TPicture::Draw(presentRect);

    TCountry** terrainDescriptors = g_apTerrainTypeDescriptorTable;
    short terrainIndex = 0;
    do {
      if (*terrainDescriptors != 0) {
        this->BlitDiplomacyMapEventPaletteMaskToSurface(terrainIndex, terrainIndex + 0x258);
      }
      terrainIndex = static_cast<short>(terrainIndex + 1);
      ++terrainDescriptors;
    } while (terrainIndex < 7);

    g_pViewMgr->SetForeColor(0x3f);

    terrainIndex = 7;
    terrainDescriptors = g_apTerrainTypeDescriptorTable + 7;
    do {
      if (*terrainDescriptors != 0) {
        this->BlitDiplomacyMapEventPaletteMaskToSurface(terrainIndex, 0x2bb);
      }
      terrainIndex = static_cast<short>(terrainIndex + 1);
      ++terrainDescriptors;
    } while (terrainIndex < 0x17);

    SetQuickDrawFillColor(0);
    DrawNames(presentRect);

    if (previousSurface != g_pPrimaryRenderSurfaceContext) {
      UnlockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
    }

    SetGWorld(previousSurface, contextFlags);
    SetQuickDrawColorAndSyncGlobals(savedForegroundColor);
    SetGlobalBlitTransparentColorRaw(savedBackgroundColor);
    legendSurfaceMode = 0;
  }

  if (g_pPrimaryRenderSurfaceContext->GetBlitSurface() !=
      g_pActiveQuickDrawSurfaceContext->GetBlitSurface()) {
    RECT blitRect;
    CopyRect(&blitRect, presentRect);
    BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect,
                                     &blitRect, 0);
  }

  SetQuickDrawFillColor(0xffffff);
  RgnHandle frameRegion = g_pMacViewMgr->GetCountryRegion(static_cast<short>(frameRegionSelector));
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
      RgnHandle frameRegion = g_pMacViewMgr->GetCountryRegion(static_cast<short>(terrainIndex));
      UnionRgn(region, frameRegion, region);
    }
    terrainIndex = static_cast<short>(terrainIndex + 1);
    ++terrainDescriptors;
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

  if (legendSurfaceMode != 4) {
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
          &maskOrigin, true);

      int packedColor = g_pViewMgr->GetColor(0x3f);
      packedColorRuns[nationIndex].AppendPackedColorDword(
          g_pActiveQuickDrawSurfaceContext->blitSurface.pixelBits, packedColor);

      nationIndex = static_cast<short>(nationIndex + 1);
    } while (nationIndex < kNationSlotCount);

    DrawNames(presentRect);
    legendSurfaceMode = 4;
    UnlockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
    SetGWorld(previousSurface, contextFlags);
  }

  BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect,
                                   &blitRect, 0);
}

// FUNCTION: IMPERIALISM 0x004f66c0
void DiplomacyMaskBufferRun::BlitMonochromeMaskBytePatternToSurface(TQuickDrawBlitSurface* surface,
                                                                    TUiStyleRef paletteColor,
                                                                    const CPoint* origin,
                                                                    bool flipVertical) {
  unsigned char* maskCursor = maskBytes;
  if (maskCursor == 0) {
    return;
  }

  int rowStride = surface->stride;
  unsigned int row = bounds.top;
  unsigned char* destCursor;
  int rowAdvance;
  if (!flipVertical) {
    destCursor = surface->pixelBits + (origin->y + row) * rowStride + origin->x + bounds.left;
    rowAdvance = bounds.left + (rowStride - bounds.right);
  } else {
    int surfaceHeight = surface->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (surfaceHeight < 1) {
      surfaceHeight = -surfaceHeight;
    }
    destCursor = surface->pixelBits + (((surfaceHeight - origin->y) - row) - 1) * rowStride +
                 origin->x + bounds.left;
    rowAdvance = bounds.left + (-rowStride - bounds.right);
  }

  if (static_cast<int>(row) < bounds.bottom) {
    do {
      int x = bounds.left;
      unsigned char* rowCursor = destCursor;
      if (x < bounds.right) {
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
              bit *= 2;
              x += 1;
              destCursor += 1;
            } while (bit < 0x100);
          }
          maskCursor += 1;
          rowCursor = destCursor;
        } while (x < bounds.right);
      }
      row += 1;
      destCursor += rowAdvance;
    } while (static_cast<int>(row) < bounds.bottom);
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
  frameRegionSelector = (short)activeNationSlot;

  TQuickDrawSurfaceContext* previousSurface = 0;
  CPoint maskOrigin;
  int contextFlags = 0;
  RECT blitRect;
  blitRect.left = presentRect->left;
  blitRect.top = presentRect->top;
  blitRect.right = presentRect->right;
  blitRect.bottom = presentRect->bottom;

  if (legendSurfaceMode != 1) {
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
            &maskOrigin, true);

        int packedColor = g_pViewMgr->GetColor(0x3f);
        packedColorRuns[terrainIndex].AppendPackedColorDword(
            g_pActiveQuickDrawSurfaceContext->blitSurface.pixelBits, packedColor);
      }
      terrainIndex++;
      terrainDescriptors++;
    } while (terrainIndex < 0x17);

    DrawNames(presentRect);
    legendSurfaceMode = 1;
    UnlockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
    SetGWorld(previousSurface, contextFlags);
  }

  BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect,
                                   &blitRect, 0);
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
                                                  static_cast<short>(paletteIndex), &maskOrigin,
                                                  true);

  int packedColor = g_pViewMgr->GetColor(0x3f);
  StrategicMapCallbackRecord* packedRun = &packedColorRuns[maskIndex];
  packedRun->AppendPackedColorDword(g_pActiveQuickDrawSurfaceContext->blitSurface.pixelBits,
                                    packedColor);
}

// FUNCTION: IMPERIALISM 0x004f6bd0
void TDiplomacyMapView::BlitDiplomacyMapEventPaletteMaskToSurface(short maskIndex, int bmpId) {
  TQuickDrawSurfaceContext* surface = g_pActiveQuickDrawSurfaceContext;
  DiplomacyMaskBufferRun* maskRun = &maskRuns[maskIndex];
  CDib* bmpHandle = g_pResourceMgr->LoadBmpResourceByIdCached(static_cast<unsigned short>(bmpId));

  unsigned char* maskCursor = maskRun->maskBytes;
  if (maskCursor != 0) {
    int srcRowWidth = bmpHandle->m_pInfoHeader->bmiHeader.biWidth;
    int srcRowAdvance =
        (((srcRowWidth + 3) & 0xfffffffc) - maskRun->bounds.right) + maskRun->bounds.left;
    int surfaceHeight = surface->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (surfaceHeight < 1) {
      surfaceHeight = -surfaceHeight;
    }
    int row = maskRun->bounds.top;
    int rowStride = surface->blitSurface.stride;
    unsigned char* destCursor = surface->blitSurface.pixelBits +
                                ((surfaceHeight - row) - 1) * rowStride + maskRun->bounds.left;
    int destRowAdvance = (maskRun->bounds.left - maskRun->bounds.right) - rowStride;
    unsigned char* srcCursor = static_cast<unsigned char*>(bmpHandle->m_dibBits);

    if (row < maskRun->bounds.bottom) {
      do {
        int x = maskRun->bounds.left;
        if (x < maskRun->bounds.right) {
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
                bit *= 2;
                x += 1;
                destCursor += 1;
                srcCursor += 1;
              } while (bit < 0x100);
            }
            maskCursor += 1;
          } while (x < maskRun->bounds.right);
        }
        row += 1;
        srcCursor += srcRowAdvance;
        destCursor += destRowAdvance;
      } while (row < maskRun->bounds.bottom);
    }
  }

  g_pResourceMgr->ReleaseRecordByHandle(bmpHandle);
  int packedColor = g_pViewMgr->GetColor(0x3f);
  StrategicMapCallbackRecord* packedRun = &packedColorRuns[maskIndex];
  packedRun->AppendPackedColorDword(surface->GetBlitSurface()->pixelBits, packedColor);
}

// FUNCTION: IMPERIALISM 0x004f6d90
void TDiplomacyMapView::ChangeSelectedActionTopic(int topicIndex) {
  int newTopic = topicIndex;
  if (g_pSimMgr->mode == kGamePhaseDiplomacy) {
    if (newTopic == 2 || newTopic == 3) {
      return;
    }
    if (newTopic == 1) {
      newTopic = 5;
    }
  }

  if (stateFlag == newTopic) {
    return;
  }

  CPoint layoutPosition(0x39, 0x320);
  actionButtons[stateFlag]->Locate(layoutPosition, true);
  layoutPosition.y = 0x162;
  actionButtons[newTopic]->Locate(layoutPosition, true);

  TPicture* ltabControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagLtab));
  ltabControl->AssertValid();
  TPicture* rtabControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagRtab));
  rtabControl->AssertValid();

  if (newTopic == 0 || newTopic == 4) {
    ltabControl->Show(1, 1);
    rtabControl->Show(0, 1);
    if (newTopic == 0) {
      ltabControl->SetPictureRsrcID(0x1389, 1);
    } else {
      ltabControl->SetPictureRsrcID(0x138a, 1);
    }
  } else {
    ltabControl->Show(0, 1);
    rtabControl->Show(1, 1);
    if (g_pSimMgr->mode == kGamePhaseDiplomacy) {
      rtabControl->SetPictureRsrcID(0x20da, 1);
    } else {
      rtabControl->SetPictureRsrcID(static_cast<short>(newTopic + 0x138a), 1);
    }
  }

  this->ForceRedraw();
  stateFlag = newTopic;

  switch (newTopic) {
  case 0:
    interactionMode = 0;
    break;
  case 1:
    interactionMode = 4;
    break;
  case 2:
    interactionMode = 1;
    break;
  case 3:
    interactionMode = 2;
    break;
  case 4:
    interactionMode = 5;
    break;
  case 5:
    interactionMode = 0;
    break;
  }

  static_cast<TPanelView*>(actionButtons[newTopic])->Setup();

  if (selectedTerrainIndex != frameRegionSelector) {
    frameRegionSelector = selectedTerrainIndex;
    legendSurfaceMode = 6;
  }

  InvalidateCityDialogRectRegion(&mapViewportRect, 1);
}

// FUNCTION: IMPERIALISM 0x004f7040
char TDiplomacyMapView::PoseWarOffer(short sourceNationSlot, int minorNationSlot,
                                     int enemyNationSlot, int promptCode) {
  ChangeSelectedActionTopic(5);
  return static_cast<TOffersPanelView*>(actionButtons[5])
      ->PoseWarOffer(sourceNationSlot, minorNationSlot, enemyNationSlot, promptCode);
}

// FUNCTION: IMPERIALISM 0x004f7080
void TDiplomacyMapView::PoseOffer(short sourceNation, short targetNation, short offerType) {
  ChangeSelectedActionTopic(5);
  static_cast<TOffersPanelView*>(actionButtons[5])
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
  if (stateFlag == 5) {
    actionButtons[5]->DoKeyEvent(event);
    return;
  }
  TEventHandler::DoKeyEvent(event);
}

// FUNCTION: IMPERIALISM 0x004f7170
void TDiplomacyMapView::SetOverlay(int overlay) {
  interactionMode = overlay;
  InvalidateCityDialogRectRegion(&mapViewportRect, 1);
}

// FUNCTION: IMPERIALISM 0x004f71a0
void TDiplomacyMapView::DrawVoteNuggets() {
  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithDefaultFallback(0x10);

  short selectedTier = visibleVoteTier;
  int policyIndex = 0;
  do {
    short tierValue = g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix[policyIndex];
    int iconCode = g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix[policyIndex];
    if (tileHasOwnerFlags[policyIndex] && iconCode != -1 && tierValue <= selectedTier) {
      RECT* iconRect = &tileMarkerRects[policyIndex];
      short iconX = g_pGlobalMapState->GetFortFlagOffset(iconCode);

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

      BlitRectWithOptionalTransparency(g_pMacViewMgr->mapArtWorld->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                       &destRect, 0x24);

      destRect.left = iconRect->left - 1;
      destRect.top = iconRect->top - 1;
      destRect.right = iconRect->right + 1;
      destRect.bottom = iconRect->bottom + 1;
      if (tierValue == selectedTier) {
        g_pViewMgr->SetForeColor(6);
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
  } while (policyIndex < kProvinceCount);

  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x004f7400
void ShowDiplomacyActionRejectedNotice() {
  CString message;
  g_pSimMgr->GetString(0x2754, g_pDiplomacyTurnStateManager->proposalArrayMode - 1, &message);
  g_pViewMgr->ModalMessage(3, CString(g_szEmptyString), message, g_ptDiplomacyNoticeModalMessage, 0,
                           0);
}

// FUNCTION: IMPERIALISM 0x004f74f0
bool TDiplomacyMapView::CheckEntanglements(int targetNationSlot, eDipAction action) {
  if (g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(targetNationSlot,
                                                                  selectedTerrainIndex)) {
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

    entangledNations = CString(g_pDiplomacyPanelEmptyText);
    for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(static_cast<short>(targetNationSlot),
                                                          static_cast<short>(nationSlot))) {
        CString nationName;
        g_apTerrainTypeDescriptorTable[nationSlot]->FormatOverlayTerrainLabelText(&nationName);
        entangledNations += "   " + nationName + "\n";
      }
    }

    templateText = formattedIntro + "\n" + entangledNations + unusedSuffix;
    g_pSimMgr->GetString(0x275d, 5, &title);
    return g_pViewMgr->ModalMessage(3, title, templateText, g_ptDiplomacyNoticeModalMessage, 0, 0);
  }
  return true;
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
  return activeNation;
}

short TDiplomacyMapView::RuntimeRelationshipOverlaySourceNation() const {
  if (interactionMode != 1) {
    return -1;
  }
  return frameRegionSelector;
}

int TDiplomacyMapView::RuntimeActionTopicIndex() const {
  return stateFlag;
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
  RECT nationRect = nationTextHitRects[nationSlot];
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
