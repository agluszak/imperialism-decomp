#include "game/TForeignMinisterPersonalities.h"

// FUNCTION: IMPERIALISM 0x00534010
TArmsForeignMinister::TArmsForeignMinister() : TForeignMinister() {
  char* raw = reinterpret_cast<char*>(this);
  raw[0x48] = 1;
  *reinterpret_cast<short*>(raw + 0x1a) = 4;
  *reinterpret_cast<short*>(raw + 0x1c) = 0;
}

// FUNCTION: IMPERIALISM 0x005311d0
TTedForeignMinister::TTedForeignMinister() : TForeignMinister() {}

// FUNCTION: IMPERIALISM 0x00531be0
TBillForeignMinister::TBillForeignMinister() : TForeignMinister() {}

// FUNCTION: IMPERIALISM 0x00532780
TDiplomatForeignMinister::TDiplomatForeignMinister() : TForeignMinister() {}

// FUNCTION: IMPERIALISM 0x00533110
TTextileForeignMinister::TTextileForeignMinister() : TForeignMinister() {}

// FUNCTION: IMPERIALISM 0x005338a0
TTraderForeignMinister::TTraderForeignMinister() : TForeignMinister() {}
