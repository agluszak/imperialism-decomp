#pragma once

#include "game/TUberCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00665838
class TAmtBarCluster : public TUberCluster {
public:
  virtual ~TAmtBarCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;      // slot 0x0f 0x00586e70
  virtual void DoPostCreate(int styleSeed) override; // slot 0x37 0x586d60
  virtual void SetMoveAmount(short amount);          // slot 0x74 0x586ff0

  // No own fields: RTTI proves TAmtBarCluster is exactly TUberCluster's size (0x88).
  TAmtBarCluster();
  DECLARE_DYNCREATE(TAmtBarCluster)
};
