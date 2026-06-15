#pragma once

#include "game/TMinister.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 thunk_InitializeCityInteriorMinister(void);

// Player city interior minister — extends TMinister with city-policy virtuals through slot 0x35.
// VTABLE: IMPERIALISM 0x006508a8
class TCityInteriorMinister : public TMinister {
public:
  TCityInteriorMinister();
  void InitializeCityInteriorState();

  // TCityInteriorMinister-introduced extension (vtable 0x6508a8 slots 22-53). TMinister's
  // own vtable ends at slot 21; slots 22-43 are this branch's own virtuals (placeholders,
  // bodies not yet ported), then the named city-policy slots from 44 onward.
  virtual void CityInteriorSlot16();          // 22 (0x58)
  virtual void CityInteriorSlot17();          // 23 (0x5c)
  virtual void CityInteriorSlot18();          // 24 (0x60)
  virtual void CityInteriorSlot19();          // 25 (0x64)
  virtual void CityInteriorSlot1A();          // 26 (0x68)
  virtual void CityInteriorSlot1B();          // 27 (0x6c)
  virtual void CityInteriorSlot1C();          // 28 (0x70)
  virtual void CityInteriorSlot1D();          // 29 (0x74)
  virtual void CityInteriorSlot1E();          // 30 (0x78)
  virtual void CityInteriorSlot1F();          // 31 (0x7c)
  virtual void CityInteriorSlot20();          // 32 (0x80)
  virtual void CityInteriorSlot21();          // 33 (0x84)
  virtual void CityInteriorSlot22();          // 34 (0x88)
  virtual void CityInteriorSlot23();          // 35 (0x8c)
  virtual void CityInteriorSlot24();          // 36 (0x90)
  virtual void CityInteriorSlot25();          // 37 (0x94)
  virtual void CityInteriorSlot26();          // 38 (0x98)
  virtual void CityInteriorSlot27();          // 39 (0x9c)
  virtual void CityInteriorSlot28();          // 40 (0xa0)
  virtual void CityInteriorSlot29();          // 41 (0xa4)
  virtual void CityInteriorSlot2A();          // 42 (0xa8)
  virtual void CityInteriorSlot2B();          // 43 (0xac)
  virtual void CityInteriorSlot2C();          // 44 (0xb0)
  virtual void CityInteriorSlot2D();          // 45
  virtual void CityInteriorSlot2E();          // 46
  virtual void CityInteriorSlot2F();          // 47
  virtual int GetHomeCityRecordIndexSlotC0(); // 48 (0xc0)
  virtual void CityInteriorSlot31();          // 49
  virtual void CityInteriorSlot32();          // 50
  virtual void CityInteriorSlot33();          // 51
  virtual void CityInteriorSlot34();          // 52 (0xd0)
  virtual void CallD4();                      // 53 (0xd4)

  void* operator new(unsigned int size) {
    (void)size;
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(0x1c4));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }
};
