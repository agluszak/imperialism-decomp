#pragma once

// Unified game NationState. Two translation units previously defined their own
// local NationState (a virtual-dispatch view in diplomacy_state.cpp and a data
// layout in trade_screen.cpp) inside anonymous namespaces to avoid an ODR
// clash. They are the same game object, so model it once: the virtual slots
// define the native vtable used by the diplomacy turn logic, and the data
// fields (after the vptr at offset 0) carry the trade-screen state.

struct NationState {
  virtual void ns_slot0() = 0;
  virtual void ns_slot1() = 0;
  virtual void ns_slot2() = 0;
  virtual void ns_slot3() = 0;
  virtual void ns_slot4() = 0;
  virtual void ns_slot5() = 0;
  virtual void ns_slot6() = 0;
  virtual void ns_slot7() = 0;
  virtual void ns_slot8() = 0;
  virtual void ns_slot9() = 0;
  virtual void ns_slot10() = 0;
  virtual void ns_slot11() = 0;
  virtual void ns_slot12() = 0;
  virtual void ns_slot13() = 0;
  virtual void ns_slot14() = 0;
  virtual void ns_slot15() = 0;
  virtual void ns_slot16() = 0;
  virtual void ns_slot17() = 0;
  virtual void SetDiplomacyStandingSlot48(int targetNation, int standing) = 0; // 18 (0x48)
  virtual void ns_slot19() = 0;
  virtual void ns_slot20() = 0;
  virtual void ns_slot21() = 0;
  virtual void ns_slot22() = 0;
  virtual char HasMinorStandingLinkSlot5C(int sourceNation) = 0; // 23 (0x5c)
  virtual void ns_slot24() = 0;
  virtual void ns_slot25() = 0;
  virtual void ns_slot26() = 0;
  virtual void ns_slot27() = 0;
  virtual void ns_slot28() = 0;
  virtual void ns_slot29() = 0;
  virtual short QueryNationMetricBySlot78(short metricSlot) = 0; // 30 (0x78)
  virtual short QueryNationMetricBySlot7C(short metricSlot) = 0; // 31 (0x7c)
  virtual void ns_slot32() = 0;
  virtual void ns_slot33() = 0;
  virtual void ns_slot34() = 0;
  virtual void ApplyTerrainDiplomacyRelationFlagSlot8c(int sourceNation,
                                                       int packedRelationCode) = 0; // 35 (0x8c)
  virtual char HasStandingPropagationBridgeSlot90(int targetNation) = 0;            // 36 (0x90)
  virtual void NotifyActionSlot94(int targetNation, int action) = 0;                // 37 (0x94)
  virtual void ns_slot38() = 0;
  virtual void ns_slot39() = 0;
  virtual void ns_slot40() = 0;
  virtual void ns_slot41() = 0;
  virtual void ns_slot42() = 0;
  virtual void ns_slot43() = 0;
  virtual void ns_slot44() = 0;
  virtual void ns_slot45() = 0;
  virtual void ns_slot46() = 0;
  virtual void ns_slot47() = 0;
  virtual void ns_slot48() = 0;
  virtual void ns_slot49() = 0;
  virtual void ns_slot50() = 0;
  virtual void ns_slot51() = 0;
  virtual void ns_slot52() = 0;
  virtual void ns_slot53() = 0;
  virtual void ns_slot54() = 0;
  virtual void ns_slot55() = 0;
  virtual void ns_slot56() = 0;
  virtual void ns_slot57() = 0;
  virtual void ns_slot58() = 0;
  virtual void ns_slot59() = 0;
  virtual void ns_slot60() = 0;
  virtual void ns_slot61() = 0;
  virtual void ns_slot62() = 0;
  virtual void ns_slot63() = 0;
  virtual void ns_slot64() = 0;
  virtual void ns_slot65() = 0;
  virtual void ns_slot66() = 0;
  virtual void ns_slot67() = 0;
  virtual void ns_slot68() = 0;
  virtual void ns_slot69() = 0;
  virtual void ns_slot70() = 0;
  virtual void ns_slot71() = 0;
  virtual void ns_slot72() = 0;
  virtual void ns_slot73() = 0;
  virtual void ns_slot74() = 0;
  virtual void ns_slot75() = 0;
  virtual void ns_slot76() = 0;
  virtual void ns_slot77() = 0;
  virtual void ns_slot78() = 0;
  virtual void ns_slot79() = 0;
  virtual void ns_slot80() = 0;
  virtual void ns_slot81() = 0;
  virtual void ns_slot82() = 0;
  virtual void ns_slot83() = 0;
  virtual void ns_slot84() = 0;
  virtual void ns_slot85() = 0;
  virtual void ns_slot86() = 0;
  virtual void ns_slot87() = 0;
  virtual void ns_slot88() = 0;
  virtual void ns_slot89() = 0;
  virtual void ns_slot90() = 0;
  virtual void ns_slot91() = 0;
  virtual void ns_slot92() = 0;
  virtual void ns_slot93() = 0;
  virtual void ns_slot94() = 0;
  virtual void ns_slot95() = 0;
  virtual void ns_slot96() = 0;
  virtual void ns_slot97() = 0;
  virtual void ns_slot98() = 0;
  virtual void ns_slot99() = 0;
  virtual void ns_slot100() = 0;
  virtual void ns_slot101() = 0;
  virtual void ns_slot102() = 0;
  virtual void ns_slot103() = 0;
  virtual void ns_slot104() = 0;
  virtual void ns_slot105() = 0;
  virtual void ns_slot106() = 0;
  virtual void ns_slot107() = 0;
  virtual void ns_slot108() = 0;
  virtual void ns_slot109() = 0;
  virtual void ns_slot110() = 0;
  virtual void ns_slot111() = 0;
  virtual void ns_slot112() = 0;
  virtual void ns_slot113() = 0;
  virtual void BeginTurnDiplomacyPrePassSlot1c8() = 0; // 114 (0x1c8)
  virtual void RefreshTurnDiplomacyStateSlot1cc() = 0; // 115 (0x1cc)
  virtual void ns_slot116() = 0;
  virtual void ns_slot117() = 0;
  virtual void
  RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8(int sourceNation) = 0; // 118 (0x1d8)
  virtual void ns_slot119() = 0;
  virtual void ApplyTurnDiplomacyStateSlot1e0() = 0; // 120 (0x1e0)
  virtual void ns_slot121() = 0;
  virtual void ns_slot122() = 0;
  virtual void ns_slot123() = 0;
  virtual void ns_slot124() = 0;
  virtual void ns_slot125() = 0;
  virtual void ns_slot126() = 0;
  virtual void ns_slot127() = 0;
  virtual void ns_slot128() = 0;
  virtual void ns_slot129() = 0;
  virtual void ns_slot130() = 0;
  virtual void ns_slot131() = 0;
  virtual void ns_slot132() = 0;
  virtual void NotifyAllianceSlot214(int targetNation) = 0; // 133 (0x214)
  virtual void ns_slot134() = 0;
  virtual void ns_slot135() = 0;
  virtual void ns_slot136() = 0;
  virtual void ns_slot137() = 0;
  virtual void ns_slot138() = 0;
  virtual void ns_slot139() = 0;
  virtual void ns_slot140() = 0;
  virtual void ns_slot141() = 0;
  virtual void ns_slot142() = 0;
  virtual void ns_slot143() = 0;
  virtual void ns_slot144() = 0;
  virtual void ns_slot145() = 0;
  virtual void ns_slot146() = 0;
  virtual void ns_slot147() = 0;
  virtual void ns_slot148() = 0;
  virtual void ns_slot149() = 0;
  virtual void ns_slot150() = 0;
  virtual void ns_slot151() = 0;
  virtual void ns_slot152() = 0;
  virtual void ns_slot153() = 0;
  virtual void ns_slot154() = 0;
  virtual void ns_slot155() = 0;
  virtual void ns_slot156() = 0;
  virtual void ns_slot157() = 0;
  virtual void ns_slot158() = 0;
  virtual int CheckTransitionSlot27C(int targetNation, int sourceNation) = 0; // 159 (0x27c)
  virtual int PropagateWarTransitionSlot280(int targetNation, int sourceNation,
                                            int mode) = 0; // 160 (0x280)
  virtual void ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(int targetNation,
                                                                    int relationCode,
                                                                    int mode) = 0; // 161 (0x284)
  virtual void ns_slot162() = 0;
  virtual void ns_slot163() = 0;
  virtual void NotifyWarResetSlot290() = 0; // 164 (0x290)
  virtual void ns_slot165() = 0;
  virtual void ns_slot166() = 0;
  virtual void ns_slot167() = 0;
  virtual void ns_slot168() = 0;
  virtual void ns_slot169() = 0;
  virtual void NotifyRelationCodeSlot2A8(int targetNation, int relationCode) = 0; // 170 (0x2A8)

  // Data layout (trade screen). The C++ vptr occupies offset 0, matching the
  // game object's vtable pointer; explicit fields follow.
  char pad_04[0xa0];
  short tradeCapacity; // 0xa4
  char pad_a6[0x7ee];
  void* cityState; // 0x894 (NationCityTradeState* in trade screen)
};
