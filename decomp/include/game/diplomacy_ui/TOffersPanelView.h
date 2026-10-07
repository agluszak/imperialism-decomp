#pragma once

#include "compat.h"
#include "game/ui_tags_common.h"
#include "game/app/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00655fb0
class TOffersPanelView : public TPanelView {
public:
  DECLARE_DYNCREATE(TOffersPanelView)
  virtual ~TOffersPanelView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual bool PoseOffer(short sourceNation, short targetNation, short offerType);
  char PoseWarOffer(short sourceNationSlot, int minorNationSlot, int enemyNationSlot,
                    int promptCode);
  int lastNegotiationResponseTag;
  // The 'acce'/'reje' hotspot controls, resolved by DoPostCreate.
  class TPictureButton* acceptButton; // tag 'acce'
  class TPictureButton* rejectButton; // tag 'reje'

  TOffersPanelView();
};

ASSERT_SIZE(TOffersPanelView, 0x70);
