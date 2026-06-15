#pragma once

#include "game/TCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65f210
class TUberCluster : public TCluster {
public:
  void HandleTradeMoveControlAdjustment(int commandId, void* eventArg, int eventExtra);
  TUberCluster();
  CRuntimeClass* GetRuntimeClass() override;

  // Slot 0x1CC (0x73) — concrete; default returns true. Subclasses (TTradeCluster) override.
  virtual int IsTradeControlAtMinimum();

  // Slots 0x1D0 - 0x1EC (0x74 - 0x7B). NOTE: the original's TUberCluster vtable has these 8
  // slots NULL (abstract: filled only by concrete cluster subclasses, hand-constructed via
  // manual-vptr factories). We cannot model that cleanly: pure virtuals emit _purecall (not
  // NULL) under MSVC500, and the base IsTradeControl* / HandleTradeMoveControlAdjustment code
  // makes a virtual call to slot 0x1D0 (ApplyMoveValue) which forces a base declaration. Kept
  // as concrete no-op stubs; these 8 slots therefore stay mismatched vs the NULL original.
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
