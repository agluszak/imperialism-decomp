#pragma once

#define TLOCALIZATION_VTABLE_SLOT(n) virtual void LocalizationDummy##n(void) = 0

// Ghidra class TSimMgr; global instance g_pLocalizationTable @ 0x6a20f8.
// VTABLE: IMPERIALISM 0x00662a58
class TLocalizationRuntime {
public:
  virtual void* GetClassDescDynamic() = 0;
  TLOCALIZATION_VTABLE_SLOT(01);
  TLOCALIZATION_VTABLE_SLOT(02);
  TLOCALIZATION_VTABLE_SLOT(03);
  TLOCALIZATION_VTABLE_SLOT(04);
  TLOCALIZATION_VTABLE_SLOT(05);
  TLOCALIZATION_VTABLE_SLOT(06);
  TLOCALIZATION_VTABLE_SLOT(07);
  TLOCALIZATION_VTABLE_SLOT(08);
  TLOCALIZATION_VTABLE_SLOT(09);
  TLOCALIZATION_VTABLE_SLOT(10);
  TLOCALIZATION_VTABLE_SLOT(11);
  TLOCALIZATION_VTABLE_SLOT(12);
  TLOCALIZATION_VTABLE_SLOT(13);
  TLOCALIZATION_VTABLE_SLOT(14);
  virtual short GetTurnTickSlot3C(void) = 0;
  virtual void IncrementQuarterGateTick2C() = 0;
  virtual void CallSlot44() = 0; // 17 (0x44)
  TLOCALIZATION_VTABLE_SLOT(18);
  TLOCALIZATION_VTABLE_SLOT(19);
  TLOCALIZATION_VTABLE_SLOT(20);
  TLOCALIZATION_VTABLE_SLOT(21);
  TLOCALIZATION_VTABLE_SLOT(22);
  TLOCALIZATION_VTABLE_SLOT(23);
  TLOCALIZATION_VTABLE_SLOT(24);
  TLOCALIZATION_VTABLE_SLOT(25);
  TLOCALIZATION_VTABLE_SLOT(26);
  TLOCALIZATION_VTABLE_SLOT(27);
  TLOCALIZATION_VTABLE_SLOT(28);
  TLOCALIZATION_VTABLE_SLOT(29);
  // slot 0x78 — formats a number as an ordinal display string into destString
  // (TGreatPower slot 0x0f, body 0x004d8000).
  virtual void FormatOrdinalString(int value, void* destString) = 0;
  TLOCALIZATION_VTABLE_SLOT(31);
  TLOCALIZATION_VTABLE_SLOT(32);
  virtual void GetString(short codeGroup, short offset, void* destString) = 0; // 33 (0x84)

  int GetField30(void);
  void DecrementField30Value();

  unsigned char pad04[4];
  int mode;
  unsigned char pad0c[0x2C - 0x0C];
  short quarterGateTick2c;
  short pad2e;
  int field30;
  unsigned char pad34[0x40 - 0x34];
  int runtimeSubsystemIndex;
  int redrawEnabled;
  unsigned char pad48[0x64 - 0x48];
  int field_64;
  unsigned char pad68[0x7A - 0x68];
  unsigned char gateFlag7a;
  unsigned char pad7b[0x114 - 0x7B];
  // 0x114 — nonzero switches TGreatPower seeding/home-region resolution to the
  // direct-map path (0x004d71b0 / 0x004dfae0 / 0x004df810).
  short stateFlag114;

protected:
  ~TLocalizationRuntime() {}
};
