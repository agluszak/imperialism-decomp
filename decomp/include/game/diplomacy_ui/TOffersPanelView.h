#pragma once

#include "compat.h"
#include "game/ui_tags_common.h"
#include "game/app/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00655fb0
class TOffersPanelView : public TPanelView {
public:
  DECLARE_DYNCREATE(TOffersPanelView)
  virtual ~TOffersPanelView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;           // slot 0x0f 0x004f9300
  virtual void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12 0x4f9350
  virtual void DoPostCreate(int arg) override;            // slot 0x37 0x4f8ff0
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event,
                             CPoint origin) override; // slot 0x48 0x4f9420
  virtual bool PoseOffer(short sourceNation, short targetNation,
                         short offerType); // slot 0x69 0x4f9450
  char PoseWarOffer(short sourceNationSlot, int minorNationSlot, int enemyNationSlot,
                    int promptCode);
  int lastNegotiationResponseTag; // +0x64
  // The 'acce'/'reje' hotspot controls, resolved by DoPostCreate.
  class TPictureButton* acceptButton; // +0x68, tag 'acce'
  class TPictureButton* rejectButton; // +0x6c, tag 'reje'

  TOffersPanelView();
};

ASSERT_SIZE(TOffersPanelView, 0x70);
