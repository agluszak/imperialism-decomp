// AreTileIndicesHexAdjacent, isolated in its own translation unit with a local declaration
// rather than one in TMapMgr.h. Both alternatives were measured: adding the body to
// TMapMgr.cpp, and adding only the declaration to TMapMgr.h, each moved twelve unrelated
// functions (two of them out of an exact match). The header is included widely enough that
// touching it at all is not free -- see the TU-codegen fragility note in the big-functions
// skill. Declare it here until a real caller in our source needs it.

#include "decomp_types.h"

char AreTileIndicesHexAdjacent(short tileFrom, short tileTo);

// Are two tile indices hex-adjacent on the 108x60 map? Each index splits into a row and a
// staggered raster column (column doubled, offset by the row's parity), which turns the six
// hex neighbours into a fixed set of column offsets: +-2 on the same row, +-1 on the rows
// above and below. The 0xd6/0xd7 alternatives are the same neighbours reached the other way
// around the horizontal wrap.
// FUNCTION: IMPERIALISM 0x00512f10
char AreTileIndicesHexAdjacent(short tileFrom, short tileTo) {
  short rowFrom = tileFrom / 0x6c;
  short columnFrom = static_cast<short>(rowFrom % 2 + (tileFrom % 0x6c) * 2);
  short rowTo = tileTo / 0x6c;
  short columnTo = static_cast<short>(rowTo % 2 + (tileTo % 0x6c) * 2);
  if (rowTo == rowFrom) {
    if (columnTo != columnFrom + 2 && columnTo != columnFrom - 2 && columnTo != columnFrom + 0xd6 &&
        columnTo != columnFrom - 0xd6) {
      return 0;
    }
  } else {
    if (rowTo != rowFrom + 1 && rowTo != rowFrom - 1) {
      return 0;
    }
    if (columnTo != columnFrom + 1 && columnTo != columnFrom - 1 && columnTo != columnFrom + 0xd7 &&
        columnTo != columnFrom - 0xd7) {
      return 0;
    }
  }
  return 1;
}
