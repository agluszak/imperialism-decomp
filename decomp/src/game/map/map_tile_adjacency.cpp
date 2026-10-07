#include "decomp_types.h"
#include "game/map_domain_types.h"

bool AreTileIndicesHexAdjacent(short tileFrom, short tileTo);

// FUNCTION: IMPERIALISM 0x00512f10
bool AreTileIndicesHexAdjacent(short tileFrom, short tileTo) {
  short rowFrom = tileFrom / kStrategicMapColumns;
  short columnFrom = static_cast<short>(rowFrom % 2 + (tileFrom % kStrategicMapColumns) * 2);
  short rowTo = tileTo / kStrategicMapColumns;
  short columnTo = static_cast<short>(rowTo % 2 + (tileTo % kStrategicMapColumns) * 2);
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
