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
  virtual ~TOfferDeskPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void PoseOfferSheet(short respondingNation, short offeringNation, short proposedAmount,
                              short maxAmount, short commodityType);
  short respondingNationSlot; // nation whose UI receives/responds to the offer
  short offeringNationSlot;   // offering nation, displayed as the seller
  short maxAmount;            // upper bound passed to SetDealResults's maximumAmount arg
  short commodityType;        // commodity/need-type index 0..0x16 (0/1 = Cotton+Wool pair)
  short proposedAmount;
  short suppressEventFlag;
  unsigned char padding9c;
  bool detailedErrorFlag;
  bool selectionActive;
  unsigned char padding9f;
  class TPictureButton* acceptButton;
  class TPictureButton* rejectButton;

  TOfferDeskPicture();

  void ShowAdvice();

  void SaveAndDismiss(int actionCode);

  void SwitchToBook(bool activate);
};

ASSERT_SIZE(TOfferDeskPicture, 0xa8);
