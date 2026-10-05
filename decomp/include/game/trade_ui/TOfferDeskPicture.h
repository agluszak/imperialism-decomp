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
  short respondingNationSlot; // +0x90 nation whose UI receives/responds to the offer
  short offeringNationSlot;   // +0x92 offering nation, displayed as the seller
  short maxAmount;            // +0x94 upper bound passed to SetDealResults's maximumAmount arg
  short commodityType;        // +0x96 commodity/need-type index 0..0x16 (0/1 = Cotton+Wool pair)
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

  void CreateNextTradeCommandAndFormatPrompt(int actionCode); // 0x5c04f0

  void SwitchToBook(unsigned char activate);
};

ASSERT_SIZE(TOfferDeskPicture, 0xa8);
