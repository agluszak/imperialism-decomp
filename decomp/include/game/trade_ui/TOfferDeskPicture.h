#pragma once

#include "compat.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e728
class TOfferDeskPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TOfferDeskPicture)
  virtual ~TOfferDeskPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;           // slot 0x0f 0x005bf740
  virtual void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12 0x5bf860
  virtual void DoPostCreate(int arg) override;            // slot 0x37 0x5be600
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event,
                             CPoint origin) override; // slot 0x48 0x5c0930
  virtual void PoseOfferSheet(short respondingNation, short offeringNation, short proposedAmount,
                              short maxAmount, short commodityType); // slot 0x73 0x5bea00
  // TPicture's own slice ends at 0x90 (ASSERT_SIZE); RTTI oracle confirms
  // sizeof(TOfferDeskPicture) == 0xa8. The ctor initializes the selection flag and
  // resolves the accept/reject controls during DoPostCreate().
  // 0x90/0x92/0x96 identified from RefreshSelectedNationOrderCompatibilityInfo (hedged
  // names); 0x94/0x98/0x9a/0x9d identified from CreateNextTradeCommandAndFormatPrompt
  // (0x5c04f0): all four feed TTradeMgr::SetDealResults's arguments or the
  // quantity-validation / error-detail branches there.
  short respondingNationSlot; // +0x90 nation whose UI receives/responds to the offer
  short offeringNationSlot;   // +0x92 offering nation, displayed as the seller
  short maxAmount;            // +0x94 upper bound passed to SetDealResults's maximumAmount arg
  short commodityType;        // +0x96 commodity/need-type index 0..0x16 (0/1 = Cotton+Wool pair)
  // +0x98 current proposed quantity, refreshed from the 'purc' TNumberText control's window
  // text each time CreateNextTradeCommandAndFormatPrompt runs; forced to 0 on a 'reje' action.
  short proposedAmount;
  // +0x9a the 'clus'->'nomo' child control's IsTradeControlAtMinimum() result, forwarded as
  // SetDealResults's shortfallFlag arg (skip the diplomacy event when the
  // quantity control was never moved off its floor).
  short suppressEventFlag;
  unsigned char padding9c;
  // +0x9d gates the out-of-range quantity error message: concise (GetString group 0x2740
  // index 0x10) when set, else a detailed bracket-expanded "max is <N>" message.
  unsigned char detailedErrorFlag;
  bool selectionActive;
  unsigned char padding9f;
  class TPictureButton* acceptButton;
  class TPictureButton* rejectButton;

  TOfferDeskPicture();

  // Rebuilds the 'info' static-text control's trade-compatibility text for the responding
  // nation / offering nation / commodity, at the current help detail level.
  // 0x005bf930, __thiscall (non-virtual helper called by slot 0x73 and DoEvent).
  void RefreshSelectedNationOrderCompatibilityInfo();

  // Reads the 'clus'/'nomo'/'purc' child controls, validates the proposed quantity against
  // the 'purc' TNumberText's own maximumValue -- showing an out-of-range error and
  // re-selecting the field's text on failure -- then on success dispatches the trade
  // proposal through TTradeMgr, resets the accept/reject buttons, notifies the toolbar of
  // the new source-nation move value, and (unless mid-turn-processing) queues a new
  // TNextTradeCommand onto the UI root controller. `actionCode` is the triggering button's
  // FourCC tag ('acce'/'reje'/etc.); 'reje' forces the proposed quantity to 0.
  void CreateNextTradeCommandAndFormatPrompt(int actionCode); // 0x5c04f0

  // Updates the trade-desk selection state (activating/deactivating) and refreshes the UI
  // to match. 0x5c09d0, __thiscall.
  void UpdateTradeSelectionStateAndRefreshUiIfChanged(unsigned char activate);
};

ASSERT_SIZE(TOfferDeskPicture, 0xa8);
