#pragma once

#include "compat.h"

#include "game/ui_screens/TUberCluster.h"

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
  // The binary carries an unreferenced COMDAT copy at 0x586ce0; our build expands
  // the body inline at every site and emits no standalone symbol, so the copy is
  // claimed ownership-only.
  // SYNTHETIC: IMPERIALISM 0x00586ce0
  // ownership-only
  TAmtBarCluster() : TUberCluster() {}
  DECLARE_DYNCREATE(TAmtBarCluster)
};
ASSERT_SIZE(TAmtBarCluster, 0x88);
