#pragma once

#include "decomp_types.h"

struct CRuntimeClass;

int AllocateWithFallbackHandler(undefined4 size_bytes);

// Town/region marker record (0x50 bytes) kept on TGreatPower::townMarkerList.
// Created by the slot 0x3a/0x3b bodies ("Frog City"/"FrogCity" markers); the
// transport-link predicate 0x005b7830 reads regionId14/enabledFlag4d.
// VTABLE: IMPERIALISM 0x0066d7c8
class TTown {
public:
  virtual CRuntimeClass* GetRuntimeClass() const;

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

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }

protected:
  ~TTown() {}
};
