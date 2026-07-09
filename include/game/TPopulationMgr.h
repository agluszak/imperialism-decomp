#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

class TPopulationMetricBucket {
public:
  void* vftable;
  short valueAt4;
  short valueAt6;
  short valueAt8;
};

// TODO(manifest): describe TPopulationMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TPopulationMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064f9b0
class TPopulationMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (TPopulationMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TPopulationMgr)
  virtual ~TPopulationMgr() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4b6850
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b68f0
  virtual void Free() override;                    // slot 0x07 0x4b6990
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanLeaf_NoCall_Ins09_004b5d10(int param_1,
                                                     int param_2); // slot 0x0a 0x4b5d10
  virtual undefined OrphanLeaf_NoCall_Ins47_004b5dc0(short param_1, short param_2,
                                                     short param_3); // slot 0x0b 0x4b5dc0
  virtual undefined OrphanLeaf_NoCall_Ins20_004b5d50(short param_1); // slot 0x0c 0x4b5d50
  virtual undefined OrphanLeaf_NoCall_Ins87_004b66a0(short param_1,
                                                     short param_2); // slot 0x0d 0x4b66a0
  virtual undefined
  Helper_Uses_thunk_DeleteObjectIfNonNullViaVslot04_At004b5ed0(); // slot 0x0e 0x4b5ed0
  virtual undefined OrphanLeaf_NoCall_Ins111_004b6260(short* param_1,
                                                      ushort* param_2); // slot 0x0f 0x4b6260
  virtual undefined OrphanCallChain_C2_I61_004b65b0();                  // slot 0x10 0x4b65b0
  virtual undefined OrphanCallChain_C2_I24_004b5e80();                  // slot 0x11 0x4b5e80
  virtual undefined OrphanLeaf_NoCall_Ins50_004b63e0();                 // slot 0x12 0x4b63e0
  virtual undefined OrphanLeaf_NoCall_Ins26_004b67e0(short param_1,
                                                     short param_2); // slot 0x13 0x4b67e0
  virtual undefined OrphanLeaf_NoCall_Ins63_004b64c0();              // slot 0x14 0x4b64c0
  // === END GENERATED DECLS (TPopulationMgr) ===

  void NotifyProductionPresetSlot2C(int a, int b, int c) {
    OrphanLeaf_NoCall_Ins47_004b5dc0(static_cast<short>(a), static_cast<short>(b),
                                     static_cast<short>(c));
  }
  short* GetSummaryArraySlot50();

  unsigned char pad04[0x08 - 0x04];
  short fieldAt8; // +0x08 — snapshotted by the turn-event-0x2c packet
  unsigned char pad0a[2];
  int fieldAtC;                                 // +0x0c — snapshotted by the turn-event-0x2c packet
  TPopulationMetricBucket* baselineSlots10;     // +0x10
  TPopulationMetricBucket* productionSlots14;   // +0x14
  TPopulationMetricBucket* pendingDeltaSlots18; // +0x18
  short stockLevel1c;                           // +0x1c — low-stock flag / trade production cap
  short extraAt1e;                              // +0x1e
  short fieldAt20;                              // +0x20 — snapshotted by the turn-event-0x2c packet

  TPopulationMgr();
};
