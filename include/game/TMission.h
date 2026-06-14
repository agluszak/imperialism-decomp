#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/CRuntimeClass.h"
#include "game/TObject.h"

struct CArchive;

// Mac: TMission — base AI-mission class. Real polymorphic MFC object rooted at
// CObject<-TObject (slot 0x00 RTTI, dtor resets vptr to the CObject sentinel
// 0x66fec4). Single-inheritance base of TNavyMission / TArmyMission (and through
// them every concrete mission); proven by vtable prefix-sharing and ctor sequencing
// (ConstructTArmyMissionWithNodeKey calls ConstructTMission then installs its vtable).
//
// 48-slot vtable: slots 0x00-0x04 are the MFC CObject prefix (0x00 RTTI + 0x01 dtor
// overridden here; 0x02 Serialize / 0x03 AssertValid / 0x04 Dump inherited). Slots
// 0x05-0x26 are TMission's own virtuals (mostly default stubs concrete missions
// override). Slots 0x27-0x2f are pure virtuals (NULL in the base table). See memory
// tmission-vtable-layout-ground-truth.
//
// VTABLE: IMPERIALISM 0x0065a4e8
class TMission : public TObject {
public:
  short nationId04;      // 0x04 source-nation id (InitializeMission...)
  short pathMarker06;    // 0x06 path/dispatch marker (set 0xffff)
  unsigned char state08; // 0x08 lifecycle state byte (ctor = 2)
  unsigned char padding09[3];
  int value0c;            // 0x0c cached score/value (ctor = 0)
  unsigned char flag10;   // 0x10 dispatch flag (SetMissionField10FromArgSlot94)
  unsigned char marker11; // 0x11 status byte (ctor = 0xff)
  unsigned char padding12[2];

  TMission();

  // Factory (0x5350d0). TEMP: still forwards to the stub until the concrete mission
  // ctors use real inheritance (plan step 4).
  static void* CreateByKindAndNodeContext(int sourceNation, int missionKind, int arg2, int arg3,
                                          int arg4);

  // --- MFC CObject prefix slots 0x00-0x04 ---
  virtual CRuntimeClass* GetRuntimeClass() override; // 0x00 0x534fb0
  virtual ~TMission();                               // 0x01 dtor 0x535080 / ??_G 0x535050
  // 0x02 Serialize / 0x03 AssertValidOrSlot0c / 0x04 DumpOrSlot10 inherited from CObject.

  // --- TMission's own virtuals, exact vtable slot order ---
  virtual void SerializeMissionState(CArchive* archive);   // 0x05 0x535820
  virtual void DeserializeMissionState(CArchive* archive); // 0x06 0x5358a0
  virtual void DeleteSelfViaScalarDtor();                  // 0x07 0x4798b0
  virtual void* InvokeObjectVtableMethod24();              // 0x08 0x4798d0 (folds w/ TZone)
  virtual void* CopyPayloadBuffer();                       // 0x09 0x415ce0 (folds w/ TEventHandler)
  virtual char ReturnFalseSlot28();                        // 0x0a 0x534c00
  virtual int ReturnZeroSlot2C(int a, int b);              // 0x0b 0x534c20 (ret 8)
  virtual void NoOpSlot30();                               // 0x0c 0x534c40
  virtual void SetStateByte8To2();                         // 0x0d 0x534c60
  virtual void ResetValue0CToZero();                       // 0x0e 0x534c80
  virtual void NoOpSlot3C();                               // 0x0f 0x534ca0
  virtual void InvokeSlots34_38_3C();                      // 0x10 0x534cc0
  virtual void NoOpSlot44();                               // 0x11 0x534cf0
  virtual void* ReturnArgSlot48(void* arg);                // 0x12 0x534d10
  virtual char ReturnFalseSlot4C(int a, int b, int c);     // 0x13 0x534d30 (ret 12)
  virtual char ReturnFalseSlot50();                        // 0x14 0x534d50
  virtual char ReturnFalseSlot54();                        // 0x15 0x534d70
  virtual int ReturnZeroSlot58();                          // 0x16 0x534d90
  virtual int ReturnZeroSlot5C();                          // 0x17 0x534db0
  virtual char ReturnFalseSlot60();                        // 0x18 0x534dd0
  virtual char ReturnFalseSlot64();                        // 0x19 0x534df0
  virtual float ReturnZeroFloatSlot68();                   // 0x1a 0x534e10
  virtual float ReturnZeroFloatSlot6C();                   // 0x1b 0x534e30
  virtual float ReturnZeroFloatSlot70();                   // 0x1c 0x534e70
  virtual float ReturnZeroFloatSlot74();                   // 0x1d 0x534e50
  virtual float ReturnZeroFloatSlot78();                   // 0x1e 0x534eb0
  virtual float ReturnZeroFloatSlot7C();                   // 0x1f 0x534e90
  virtual void NoOpSlot80(int a, int b);                   // 0x20 0x534ef0
  virtual void NoOpSlot84(int a, int b);                   // 0x21 0x534ed0 (ret 8)
  virtual void NoOpSlot88(int a, int b);                   // 0x22 0x534f30
  virtual void NoOpSlot8C(int a, int b);                   // 0x23 0x534f10
  virtual void NoOpSlot90(int a);                          // 0x24 0x534f50
  virtual void SetFlag10FromArgSlot94(unsigned char value); // 0x25 0x534f70
  virtual char ReturnFalseSlot98();                         // 0x26 0x534f90

  // Slots 0x27-0x2f are NULL in the base table (abstract: filled only by derived
  // classes). Not declared here — C++ pure virtuals would emit _purecall, not NULL,
  // and the next derived class (TNavyMission/TArmyMission) appends its own virtuals
  // starting at slot 0x27. (Same convention as TUberCluster's abstract-null region.)
};

ASSERT_SIZE(TMission, 0x14);

// Mission-node queue element: slot 0x28 dispatch hook (0x004daa80).
class TMissionNodeCallback {
public:
  virtual void s00() = 0;
  virtual void s01() = 0;
  virtual void s02() = 0;
  virtual void s03() = 0;
  virtual void s04() = 0;
  virtual void s05() = 0;
  virtual void s06() = 0;
  virtual void s07() = 0;
  virtual void s08() = 0;
  virtual void s09() = 0;
  virtual void DispatchSlot28() = 0;

protected:
  ~TMissionNodeCallback() {}
};
