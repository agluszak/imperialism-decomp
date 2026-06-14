#include "game/TMinisterBaseOrderArray.h"

TMinisterBaseOrderArray::TMinisterBaseOrderArray() : TIndexAndRankList() {
  *reinterpret_cast<unsigned short*>(reinterpret_cast<char*>(this) + 0x14) = 6;
}
