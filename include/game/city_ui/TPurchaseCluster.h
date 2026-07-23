#pragma once

#include "compat.h"
#include "game/ui_core/TCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00652210
class TPurchaseCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TPurchaseCluster)
  virtual ~TPurchaseCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004cc490
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x4cc470
  // Adopts the 'valu' amount control and pushes its current value into it.
  virtual void SetValueControlAndSyncAmount(TEventHandler* control); // slot 0x73 0x4cc440
  // Real params are (short nValue, char redrawFlag) -- confirmed from the callsite
  // (0x4cc490: pushes field88's word field then 1) and the body's own stack reads
  // ([esp+0x2c]=nValue, [esp+0x30]=redrawFlag). The previous (int*, short) declaration
  // was a poison-pill guess; there is no pCityViewDialog parameter.
  virtual void SetCityViewValueControlAmount(short nValue, char redrawFlag); // slot 0x74 0x4cc550
  // DoEvent applies DEC/INC to this call's result before feeding it back, so the slot
  // returns the control's current amount rather than nothing.
  virtual int UpdateCityViewValueControl(); // slot 0x75 0x4cc640
  // TCluster's slice ends at 0x88; RTTI oracle confirms sizeof(TPurchaseCluster) == 0x8c.
  // The ctor (0x4cc3c0) zeroes the one own field. DoEvent dispatches
  // field88->vtbl[0x2c] (TEventHandler::SetEnable) and then reads a short at
  // field88's own +0x4 -- exactly TEventHandler::field04's low word (TEventHandler has no
  // data before field04; TObject/CObject contribute only the vtable pointer), so field88
  // is plain TEventHandler*, not an unresolved subtype.
  class TEventHandler* field88; // +0x88

  TPurchaseCluster();
};

ASSERT_SIZE(TPurchaseCluster, 0x8c);
