#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

struct CRuntimeClass;

// Town/region marker record (0x50 bytes) kept on TGreatPower::townMarkerList.
// VTABLE: IMPERIALISM 0x0066d7c8
class TTown : public TObject {
public:
  DECLARE_DYNCREATE(TTown)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  // slot 0x1c Free inherited unchanged (TObject::Free @ 0x004798b0)

  char name[0x10];                      // 0x04 — strcpy'd marker name
  short regionId14;                     // 0x14
  unsigned char flags16[4];             // 0x16..0x19 — cleared on init
  short createdTurnTick1a;              // 0x1a — localization tick at creation
  short ownerNation1c;                  // 0x1c
  unsigned char payload1e[0x4c - 0x1e]; // 0x1e..0x4b — cleared on init
  unsigned char transportLinkedFlag4c;  // 0x4c
  unsigned char enabledFlag4d;          // 0x4d
  unsigned char pad4e;                  // 0x4e
  unsigned char activeFlag4f;           // 0x4f

  TTown();
  void InitializeTownMarker(const char* markerName, short regionId, char enabledFlag,
                            short ownerNation);
  char IsTransportLinkedAndEnabled(void);

  ~TTown() override;
};

ASSERT_SIZE(TTown, 0x50);
