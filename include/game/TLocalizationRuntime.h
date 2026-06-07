#pragma once

#define TLOCALIZATION_VTABLE_SLOT(n) virtual void LocalizationDummy##n(void) = 0

class TLocalizationRuntime {
public:
  TLOCALIZATION_VTABLE_SLOT(00);
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

  unsigned char pad04[4];
  int mode;
  unsigned char pad0c[0x2C - 0x0C];
  short quarterGateTick2c;
  unsigned char pad2e[0x40 - 0x2E];
  int runtimeSubsystemIndex;
  int redrawEnabled;
  unsigned char pad48[0x64 - 0x48];
  int field_64;
};
