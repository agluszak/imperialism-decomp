#pragma once

#include "game/TInteriorMinister.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 thunk_InitializeCityInteriorMinister(void);

// Player city interior minister — derives from TInteriorMinister (shares slots 0x48-0x50)
// and overrides serialization/Free/NotifySlot44 plus a long city-policy virtual run.
// VTABLE: IMPERIALISM 0x006508a8
class TCityInteriorMinister : public TInteriorMinister {
public:
  TCityInteriorMinister();
  void InitializeCityInteriorState();

  CRuntimeClass* GetRuntimeClass() const override; // slot 0x00
  void WriteTo(TStream* stream) override;          // slot 0x14
  void ReadFrom(TStream* stream) override;         // slot 0x18
  void Free() override;                            // slot 0x1c
  void MinisterSlot0A() override;                  // slot 0x28
  void NotifySlot44(void* receiver) override;      // slot 0x44
  void Call54() override;                          // slot 0x54

  // TCityInteriorMinister-introduced virtuals (vtable 0x6508a8 slots 0x58-0xd4).
  virtual void CityInteriorSlot16();          // 0x58
  virtual void CityInteriorSlot17();          // 0x5c
  virtual void CityInteriorSlot18();          // 0x60
  virtual void CityInteriorSlot19();          // 0x64
  virtual void CityInteriorSlot1A();          // 0x68
  virtual void CityInteriorSlot1B();          // 0x6c
  virtual void CityInteriorSlot1C();          // 0x70
  virtual void CityInteriorSlot1D();          // 0x74
  virtual void CityInteriorSlot1E();          // 0x78
  virtual void CityInteriorSlot1F();          // 0x7c
  virtual void CityInteriorSlot20();          // 0x80
  virtual void CityInteriorSlot21();          // 0x84
  virtual void CityInteriorSlot22();          // 0x88
  virtual void CityInteriorSlot23();          // 0x8c
  virtual void CityInteriorSlot24();          // 0x90
  virtual void CityInteriorSlot25();          // 0x94
  virtual void CityInteriorSlot26();          // 0x98
  virtual void CityInteriorSlot27();          // 0x9c
  virtual void CityInteriorSlot28();          // 0xa0
  virtual void CityInteriorSlot29();          // 0xa4
  virtual void CityInteriorSlot2A();          // 0xa8
  virtual void CityInteriorSlot2B();          // 0xac
  virtual void CityInteriorSlot2C();          // 0xb0
  virtual void CityInteriorSlot2D();          // 0xb4
  virtual void CityInteriorSlot2E();          // 0xb8
  virtual void CityInteriorSlot2F();          // 0xbc
  virtual int GetHomeCityRecordIndexSlotC0(); // 0xc0
  virtual void CityInteriorSlot31();          // 0xc4
  virtual void CityInteriorSlot32();          // 0xc8
  virtual void CityInteriorSlot33();          // 0xcc
  virtual void CityInteriorSlot34();          // 0xd0
  virtual void CallD4();                      // 0xd4

  void* operator new(unsigned int size) {
    (void)size;
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(0x1c4));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }
};
