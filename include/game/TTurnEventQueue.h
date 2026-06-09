#pragma once

#include "decomp_types.h"

// Turn-event command queue reached via g_pGlobalUiRootController. ProcessQueuedWarTransitions
// enqueues a TNextTradeCommand through slot 0x38.
struct TTurnEventQueue {
  virtual void teq_slot0() = 0;
  virtual void teq_slot1() = 0;
  virtual void teq_slot2() = 0;
  virtual void teq_slot3() = 0;
  virtual void teq_slot4() = 0;
  virtual void teq_slot5() = 0;
  virtual void teq_slot6() = 0;
  virtual void teq_slot7() = 0;
  virtual void teq_slot8() = 0;
  virtual void teq_slot9() = 0;
  virtual void teq_slot10() = 0;
  virtual void teq_slot11() = 0;
  virtual void teq_slot12() = 0;
  virtual void teq_slot13() = 0;
  virtual void EnqueueSlot38(void* packet) = 0; // 14 (0x38)
};

