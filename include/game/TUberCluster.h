#pragma once

#include "game/TCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65f210
class TUberCluster : public TCluster {
public:
  void HandleTradeMoveControlAdjustment(int commandId, void* eventArg, int eventExtra);
  TUberCluster();
  virtual ~TUberCluster() override;
  CRuntimeClass* GetRuntimeClass() override;

  // Slots 0x1CC - 0x1EC (0x73 - 0x7B)
  virtual int vmethod_0115();
  virtual void ApplyMoveValue(int value);
  virtual int NotifyControlSelectionChange(void* boundEntry, int arg2 = 0);
  virtual int GetControlFlag(int arg1 = 0, int arg2 = 0);
  virtual int GetBoolSlot1DC();
  virtual void DoControlAction();
  virtual void SetTradeBidControlBitmap();
  virtual void SetTradeOfferControlBitmap();
  virtual void SetTradeOfferSecondaryBitmap();

  void InitializeTradeMoveAndBarControls(unsigned int styleSeed = 0);
};
