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

  virtual void CityInteriorSlot2C(); // 44 (0xb0)
  virtual void CityInteriorSlot2D(); // 45
  virtual void CityInteriorSlot2E(); // 46
  virtual void CityInteriorSlot2F(); // 47
  virtual int GetHomeCityRecordIndexSlotC0(); // 48 (0xc0)
  virtual void CityInteriorSlot31(); // 49
  virtual void CityInteriorSlot32(); // 50
  virtual void CityInteriorSlot33(); // 51
  virtual void CityInteriorSlot34(); // 52 (0xd0)
  virtual void CallD4(); // 53 (0xd4)

  void* operator new(unsigned int size) {
    (void)size;
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(0x1c4));
  }
  void operator delete(void* ptr) { (void)ptr; }
};
