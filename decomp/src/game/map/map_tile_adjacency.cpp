// MATCH: own translation unit, and the declaration stays local rather than going into
// TMapMgr.h -- either edit to that widely-included header perturbs a dozen unrelated
// functions. Move the declaration out when a caller in our source needs it.

#include "decomp_types.h"

bool AreTileIndicesHexAdjacent(short tileFrom, short tileTo);

// FUNCTION: IMPERIALISM 0x00512f10
bool AreTileIndicesHexAdjacent(short tileFrom, short tileTo) {
  short rowFrom = tileFrom / 0x6c;
  short columnFrom = static_cast<short>(rowFrom % 2 + (tileFrom % 0x6c) * 2);
  short rowTo = tileTo / 0x6c;
  short columnTo = static_cast<short>(rowTo % 2 + (tileTo % 0x6c) * 2);
  if (rowTo == rowFrom) {
    if (columnTo != columnFrom + 2 && columnTo != columnFrom - 2 && columnTo != columnFrom + 0xd6 &&
        columnTo != columnFrom - 0xd6) {
      return false;
    }
  } else {
    if (rowTo != rowFrom + 1 && rowTo != rowFrom - 1) {
      return false;
    }
    if (columnTo != columnFrom + 1 && columnTo != columnFrom - 1 && columnTo != columnFrom + 0xd7 &&
        columnTo != columnFrom - 0xd7) {
      return false;
    }
  }
  return true;
}
