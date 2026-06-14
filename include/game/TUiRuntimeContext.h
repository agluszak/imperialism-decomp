#pragma once

class TUiRuntimeContext {
public:
  virtual void dummy0() = 0;
  virtual void dummy1() = 0;
  virtual void dummy2() = 0;
  virtual void dummy3() = 0;
  virtual void dummy4() = 0;
  virtual void dummy5() = 0;
  virtual void dummy6() = 0;
  virtual void dummy7() = 0;
  virtual void dummy8() = 0;
  virtual void dummy9() = 0;
  virtual void dummy10() = 0;
  virtual void dummy11() = 0;
  virtual void dummy12() = 0;
  virtual void dummy13() = 0;
  virtual void dummy14() = 0;
  // 0x3c — queues a per-nation turn status prompt (TGreatPower slot 0x2d body
  // 0x004da5e0 calls this with (promptIndex 0..0xc, payload short)).
  virtual void QueueTurnStatusPromptSlot3C(int promptIndex, int payload) = 0;
  virtual void dummy16() = 0;
  virtual void dummy17() = 0;
  virtual void dummy18() = 0;
  virtual void DispatchEventSlot4C(int eventCode, int nationSlot) = 0;
  virtual void dummy20() = 0;
  virtual void dummy21() = 0;
  virtual void dummy22() = 0;
  virtual void dummy23() = 0;
  virtual void dummy24() = 0;
  virtual void dummy25() = 0;
  virtual void dummy26() = 0;
  virtual void dummy27() = 0;
  virtual void dummy28() = 0;
  virtual void dummy29() = 0;
  virtual void dummy30() = 0;
  virtual void dummy31() = 0;
  virtual void dummy32() = 0;
  virtual void dummy33() = 0;
  virtual void dummy34() = 0;
  virtual void dummy35() = 0;
  virtual char RequestDiplomacyDecisionSlot90(int sourceNation, int targetNation,
                                              int proposalCode) = 0; // slot 90
  virtual char RequestDecisionSlot94(int sourceNation, int arg1, int arg2,
                                     int promptCode) = 0; // slot 94
  virtual void DispatchDecisionSlot98(int sourceNation, int arg2, int arg3,
                                      int targetNation) = 0; // slot 98
protected:
  ~TUiRuntimeContext() {}
};
