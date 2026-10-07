#pragma once

#include "game/map_domain_types.h"
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
  CRect bounds;
};

ASSERT_SIZE(DiplomacyMaskBufferRun, 0x14);

// FUNCTION: IMPERIALISM 0x004d6310
inline bool DiplomacyMaskBufferRun::IsMaskPixelSet(int x, int y) const {
  CPoint point(x, y);
  if (PtInRect(&bounds, point) == 0) {
    return false;
  }

  int xOffset = x - bounds.left;
  int rowStride = (bounds.right - bounds.left) >> 3;
  int byteIndex = (y - bounds.top) * rowStride + (xOffset >> 3);
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
  void Free() override;
  void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void DoKeyEvent(TToolboxEvent* event) override;
  void Close() override;
  void DoSetCursor(CPoint* point, RgnHandle hitArg) override;
  void AdjustCursor(CPoint* point, RgnHandle dispatchArg) override;
  void DoPostCreate(int arg) override;
  void Draw(RECT* rectBuffer) override;
  void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;

  virtual void DrawCountries(RECT* presentRect);
  virtual void InvalidateCountries();
  virtual void ShowTreaties(int activeNationSlot, const RECT* presentRect);
  virtual void VisitNationSlotsForOverlay(int unusedMode);
  virtual void ShowRelations(int activeNationSlot, const RECT* presentRect);
  virtual void FillRegionWithPict(short maskIndex, unsigned short bmpId);
  virtual void PoseOffer(short sourceNation, short targetNation, short offerType);
  void CreateDrawGeometries();

  TDiplomacyMapView();

  eDipAction GetAction(CPoint* clickPoint);
  void PaintRegion(int maskIndex, short eventCode);
  char PoseWarOffer(short sourceNationSlot, int minorNationSlot, int enemyNationSlot,
                    int promptCode);
  void DrawVoteNuggets();
  void SetOverlay(int overlay); // Mac oracle eDipDrawStatus
  void DrawNames(const RECT* presentRect);
  void DrawIcons(RECT* presentRect);

  void SetSelectedTerrainIndexForTurnEvent(short terrainIndex) {
    selectedTerrainIndex = terrainIndex;
  }

  void PrepVariousSubviews();

  bool CheckEntanglements(int targetNationSlot, eDipAction action);

  void SwitchToPanel(int topicIndex);

#ifdef IMPERIALISM_RUNTIME_TESTS
  void ActivateNation(short nationSlot);
  short RuntimeActiveNation() const;
  short RuntimeRelationshipOverlaySourceNation() const;
  int RuntimeActionTopicIndex() const;
  short RuntimeDrawPolicyIconForNation(short nationSlot);
#endif

protected:
  short selectedTerrainIndex;
  int interactionMode;
  short frameRegionSelector;
  RgnHandle region;
  TView* actionButtons[6];
  int stateFlag;

public:
  eDipAction actionCode;
  short selectedGrantRow;

protected:
  short activeNation;
  CRect nationTextHitRects[23];
  CRect nationLabelRects[23];
  CRect nationAnchorRects[23];
  // +0x514..+0x520 -- map origin/extents.
  CRect mapViewportRect;
  int legendSurfaceMode;
  short visibleVoteTier;
  short currentCursorResourceId;
  bool tileHasOwnerFlags[kProvinceCount];
  CRect tileMarkerRects[kProvinceCount];
  DiplomacyMaskBufferRun maskRuns[23];
  StrategicMapCallbackRecord packedColorRuns[23];
};

ASSERT_SIZE(TDiplomacyMapView, 0x24c8);
