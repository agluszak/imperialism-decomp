#include "game/TDefenseMinister.h"

// FUNCTION: IMPERIALISM 0x004ec0e0
TDefenseMinister::TDefenseMinister() : TMinister() {}

// FUNCTION: IMPERIALISM 0x004ec160
void TDefenseMinister::InitializeBaseOrderArrayMetrics() {
  reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTMinisterBaseOrderArray)();
  char* raw = reinterpret_cast<char*>(this);
  *reinterpret_cast<short*>(raw + 0x10) = 0;
  *reinterpret_cast<short*>(raw + 0x12) = 0;
  *reinterpret_cast<short*>(raw + 0x8c) = 0;
  *reinterpret_cast<short*>(raw + 0x8e) = 0;
  *reinterpret_cast<short*>(raw + 0x90) = 0;
  *reinterpret_cast<short*>(raw + 0x92) = 0;
  short* cursor = reinterpret_cast<short*>(raw + 0x14);
  int remaining = 0x1e;
  do {
    cursor[0x1e] = 0;
    *cursor = 0;
    ++cursor;
    --remaining;
  } while (remaining != 0);
}
