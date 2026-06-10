#include "game/TForeignMinister.h"

// FUNCTION: IMPERIALISM 0x0052f070
TForeignMinister::TForeignMinister() : TMinister() {
  char* raw = reinterpret_cast<char*>(this);
  *reinterpret_cast<unsigned int*>(raw + 0x49) = 0x01010101;
  *reinterpret_cast<unsigned short*>(raw + 0x4d) = 0x0101;
  raw[0x4f] = 1;
  unsigned int* block = reinterpret_cast<unsigned int*>(raw + 0x50);
  for (int i = 0; i < 0xb; ++i) {
    block[i] = 0;
  }
  *reinterpret_cast<unsigned short*>(raw + 0x7c) = 0;
  *reinterpret_cast<unsigned short*>(raw + 0x16) = 0;
  raw[0x48] = 0;
  *reinterpret_cast<short*>(raw + 0x1a) = 5;
  *reinterpret_cast<short*>(raw + 0x1c) = 2;
}

// FUNCTION: IMPERIALISM 0x0052f130
void TForeignMinister::InitializeStateAndCounters() {
  reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTMinisterBaseOrderArray)();
  char* raw = reinterpret_cast<char*>(this);
  *reinterpret_cast<short*>(raw + 0x10) = static_cast<short>(0xfff6);
  *reinterpret_cast<short*>(raw + 0x12) = 0;
  *reinterpret_cast<short*>(raw + 0x14) = 0;
  *reinterpret_cast<short*>(raw + 0x18) = 0;
  unsigned int* block = reinterpret_cast<unsigned int*>(raw + 0x1e);
  for (int i = 0; i < 8; ++i) {
    block[i] = 0;
  }
  *reinterpret_cast<unsigned short*>(reinterpret_cast<char*>(block) + 0x20) = 0;
  *reinterpret_cast<unsigned int*>(raw + 0x40) = 0xfff6fff6;
  *reinterpret_cast<unsigned int*>(raw + 0x44) = 0xfff6fff6;
}
