#pragma once

#include "compat.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"
#include "game/diplomacy_domain_types.h"
#include "game/city_ui/StrategicMapCallbackRecord.h"
#include "game/ui_core/TPicture.h"
#include "game/mfc.h"
#include "game/gfx/quickdraw_regions.h"

class TUiStyleRef;
struct TQuickDrawBlitSurface;

struct DiplomacyMaskBufferRun {
  DiplomacyMaskBufferRun();
  ~DiplomacyMaskBufferRun();

  void BlitMonochromeMaskBytePatternToSurface(TQuickDrawBlitSurface* surface,
                                              TUiStyleRef paletteColor, const CPoint* origin,
                                              bool flipVertical);
  bool IsMaskPixelSet(int x, int y) const;

  unsigned char* maskBytes;
  CRect boundsAt04;
};

ASSERT_SIZE(DiplomacyMaskBufferRun, 0x14);

// FUNCTION: IMPERIALISM 0x004d6310
inline bool DiplomacyMaskBufferRun::IsMaskPixelSet(int x, int y) const {
  CPoint point(x, y);
  if (PtInRect(&boundsAt04, point) == 0) {
    return false;
  }

  int xOffset = x - boundsAt04.left;
  int rowStride = (boundsAt04.right - boundsAt04.left) >> 3;
  int byteIndex = (y - boundsAt04.top) * rowStride + (xOffset >> 3);
  return (maskBytes[byteIndex] & (1 << (xOffset & 7))) != 0;
}

bool IsMaskPixelSetAndOnRegionEdge(int x, int y, DiplomacyMaskBufferRun* run, char edgeOnly);

// VTABLE: IMPERIALISM 0x00655b68
class TDiplomacyMapView : public TPicture {
  friend class TInfoPanelView;
  friend class TOffersPanelView;

public:
  DECLARE_DYNCREATE(TDiplomacyMapView)
  // FUNCTION: IMPERIALISM 0x004f3cc0
  virtual ~TDiplomacyMapView() override {}
  void Free() override; // slot 0x07 0x4f3e60
  void DoEvent(int commandId, TEventHandler* sourceHandler,
               TEvent* event) override;           // slot 0x0f 0x4f70c0
  void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12 0x4f7130
  void Close() override;                          // slot 0x28 0x4f3e30
  void DoSetCursor(CPoint* point,
                   RgnHandle hitArg) override; // slot 0x2c 0x4f5f90
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                           RgnHandle hitArg) override; // slot 0x35
  void DoPostCreate(int arg) override;                                                 // slot 0x37
  void Draw(RECT* rectBuffer) override;                                                // slot 0x44
  void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                      CPoint origin) override; // slot 0x47 0x4f5410

  virtual void RenderDiplomacyLegendSurfaceAndPresent(RECT* presentRect); // slot 0x73
  virtual void BuildCombinedTerrainTypeRegionMaskAndDispatch();           // slot 0x74
  virtual void RebuildDiplomacyLegendPaletteMode4AndBlit(int activeNationSlot,
                                                         const RECT* presentRect); // slot 0x75
  virtual void VisitNationSlotsForOverlay(int unusedMode);                         // slot 0x76
  virtual void RebuildDiplomacyLegendPaletteMode1AndBlit(int activeNationSlot,
                                                         const RECT* presentRect); // slot 0x77
  virtual void BlitDiplomacyMapEventPaletteMaskToSurface(short maskIndex,
                                                         int bmpId); // slot 0x78
  virtual void PoseOffer(short sourceNation, short targetNation,
                         short offerType); // slot 0x79 0x4f7080
  void BuildDiplomacyNationOverlayGeometryAndHitMasks();

  TDiplomacyMapView();

  eDipAction ResolveDiplomacyActionFromClickAndUpdateTarget(CPoint* clickPoint);
  void BuildTurnEventMonochromeMaskBuffers(int maskIndex, int eventCode);
  // Mac CodeWarrior: TDiplomacyMapView::PoseWarOffer(short, long, long, long).
  char PoseWarOffer(short sourceNationSlot, int minorNationSlot, int enemyNationSlot,
                    int promptCode);
  void DrawVoteNuggets();
  void SetOverlay(int overlay); // 0x4f7170, Mac oracle eDipDrawStatus
  void DrawNames(const RECT* presentRect);
  void DrawIcons(RECT* presentRect);

  void SetSelectedTerrainIndexForTurnEvent(short terrainIndex) {
    selectedTerrainIndex = terrainIndex;
  }

  void InitializeDiplomacyMinisterActionControlsAndLabels();

  char CheckEntanglements(int targetNationSlot, eDipAction action);

  void ChangeSelectedActionTopic(int topicIndex);

#ifdef IMPERIALISM_RUNTIME_TESTS
  void ActivateNation(short nationSlot);
  short RuntimeActiveNation() const;
  short RuntimeRelationshipOverlaySourceNation() const;
  int RuntimeActionTopicIndex() const;
  short RuntimeDrawPolicyIconForNation(short nationSlot);
#endif

protected:
  short selectedTerrainIndex;
  char pad_92[0x02];
  int interactionModeAt94;
  short frameRegionSelector;
  char pad_9a[0x02];
  RgnHandle regionAt9c;
  TView* actionButtons[6];
  int stateFlag;

public:
  eDipAction actionCode;
  short selectedGrantRow;

protected:
  short activeNationC2;
  CRect nationTextHitRects[23]; // 0x0c4..0x234
  CRect nationLabelRects[23];   // 0x234..0x3a4
  CRect nationAnchorRects[23];  // 0x3a4..0x514
  // +0x514..+0x520 -- map origin/extents.
  CRect mapViewportRect;
  int legendSurfaceMode;
  short visibleVoteTier;
  short currentCursorResourceId;
  bool tileHasOwnerFlags[0x180];
  CRect tileMarkerRects[0x180]; // 0x6ac..0x1eac
  DiplomacyMaskBufferRun maskRuns[0x17];
  StrategicMapCallbackRecord packedColorRuns[0x17];
};

ASSERT_SIZE(TDiplomacyMapView, 0x24c8);
