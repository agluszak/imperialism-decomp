#pragma once

#include "game/TCluster.h"

// VTABLE: IMPERIALISM 0x65f210
class TUberCluster : public TCluster {
public:
  TUberCluster();
  virtual ~TUberCluster();

  // Slots 0x1CC - 0x1EC (0x73 - 0x7B)
  virtual void vmethod_0115();
  virtual void ApplyMoveValue(int value);
  virtual void NotifyControlSelectionChange(void* boundEntry);
  virtual char GetControlFlag();
  virtual char GetBoolSlot1DC();
  virtual void DoControlAction();
  virtual void SetTradeBidControlBitmap();
  virtual void SetTradeOfferControlBitmap();
  virtual void SetTradeOfferSecondaryBitmap();
};

