#include "game/TMapMaker.h"
#include "game/TObject.h"
#include "game/TControl.h"
#include "game/TMapMgr.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x00525950
// TMapMaker::GetRuntimeClass
IMPLEMENT_DYNAMIC(TMapMaker, TObject)

// FUNCTION: IMPERIALISM 0x00525970
TMapMaker::TMapMaker() : TObject() {}

// SYNTHETIC: IMPERIALISM 0x00525990
// TMapMaker::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005259c0
TMapMaker::~TMapMaker() {}

// FUNCTION: IMPERIALISM 0x00526710
char TMapMaker::ValidateAllColumnsHaveAssignedRegionClass() {
  bool foundEmptyColumn = false;
  for (int col = 0; col < 0x1b; ++col) {
    if (foundEmptyColumn) {
      break;
    }
    int row = 0;
    while (row < 0xf) {
      if (regionClassGrid10[row][col] != -1) {
        break;
      }
      ++row;
    }
    if (row == 0xf) {
      foundEmptyColumn = true;
    }
  }
  return foundEmptyColumn;
}

// True when every terrain class (0..0x16) that appears on the map has at least one valid
// "seed candidate" tile: a tile of land type {0,1,6,7} one of whose six hex neighbours is a
// city-region tile (tile[0]==5) whose own neighbours all share the seed tile's class. For
// each qualifying class the chosen candidate index is reservoir-sampled with the map-gen LCG.
// Grid is 108 (0x6c) columns x 60 (0x3c) rows, tile stride 0x24, tile[4] = terrain class.
// 0x005267f0.
// FUNCTION: IMPERIALISM 0x005267f0
char TMapMaker::ValidateSeedCandidateExistsForEachTerrainClass() {
  int seedFound[23];
  int seedCandidate[23];
  int i;

  int* pInit = seedFound;
  for (i = 0x17; i != 0; i = i + -1) {
    *pInit = 0;
    pInit = pInit + 1;
  }
  pInit = seedCandidate;
  for (i = 0x17; i != 0; i = i + -1) {
    *pInit = 0;
    pInit = pInit + 1;
  }

  int tileIndex = 0;
  int tileOffset = 0;
  do {
    char* tiles = mapTileGrid08;
    int cls = (int)tiles[tileOffset + 4];
    if ((cls < 0x17) && (-1 < cls)) {
      if (seedFound[cls] == 0) {
        int row = tileIndex / 0x6c;
        int col = tileIndex % 0x6c;
        char wrapFlag = g_pGlobalMapState->hexNeighborWrapHorizontally20;
        bool haveCandidate = false;
        short dir = 0;
        do {
          int idx = (int)dir;
          int nCol;
          if ((row & 1U) == 0) {
            nCol = g_hexColOffsetEvenRow_00697450[idx];
          } else {
            nCol = g_hexColOffsetOddRow_00697480[idx];
          }
          nCol = col + nCol;
          int nRow = row + g_hexRowOffset_00697468[idx];
          short nIdx;
          if (wrapFlag == '\0') {
            if (nCol < 0) {
              nCol = nCol + 0x6c;
            } else if (0x6b < nCol) {
              nCol = nCol + -0x6c;
            }
          LAB_neighbor_index:
            if ((nRow < 0) || (0x3b < nRow))
              goto LAB_neighbor_invalid;
            nIdx = (short)nCol + (short)nRow * 0x6c;
          } else {
            if ((-1 < nCol) && (nCol < 0x6c))
              goto LAB_neighbor_index;
          LAB_neighbor_invalid:
            nIdx = -1;
          }
          if ((nIdx != -1) && (idx = (int)nIdx, tiles[idx * 0x24] == '\x05')) {
            haveCandidate = true;
            int seedRow = idx / 0x6c;
            int seedCol = idx % 0x6c;
            int k = 0;
            do {
              int sCol;
              if ((seedRow & 1U) == 0) {
                sCol = g_hexColOffsetEvenRow_00697450[k];
              } else {
                sCol = g_hexColOffsetOddRow_00697480[k];
              }
              sCol = seedCol + sCol;
              int sRow = seedRow + g_hexRowOffset_00697468[k];
              if (wrapFlag == '\0') {
                if (sCol < 0) {
                  sCol = sCol + 0x6c;
                } else if (0x6b < sCol) {
                  sCol = sCol + -0x6c;
                }
              LAB_seed_neighbor_index:
                if ((sRow < 0) || (0x3b < sRow))
                  goto LAB_seed_neighbor_invalid;
                sCol = sCol + sRow * 0x6c;
              } else {
                if ((-1 < sCol) && (sCol < 0x6c))
                  goto LAB_seed_neighbor_index;
              LAB_seed_neighbor_invalid:
                sCol = -1;
              }
              char nbCls;
              if (((sCol != -1) && (nbCls = tiles[4 + sCol * 0x24], nbCls < '\x17')) &&
                  (nbCls != cls)) {
                haveCandidate = false;
                break;
              }
              k = k + 1;
            } while (k < 6);
            if (haveCandidate) {
              if ((seedCandidate[cls] == 0) ||
                  (g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1,
                   (g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 5 == 3)) {
                seedCandidate[cls] = (int)nIdx;
              }
              break;
            }
          }
          dir = dir + 1;
        } while (dir < 6);
        char typeByte;
        if (haveCandidate &&
            (((typeByte = mapTileGrid08[tileOffset], typeByte == '\0') || (typeByte == '\a')) ||
             ((typeByte == '\x01') || (typeByte == '\x06')))) {
          seedFound[cls] = 1;
        }
      }
    }
    tileOffset = tileOffset + 0x24;
    tileIndex = tileIndex + 1;
    if (0x38f3f < tileOffset) {
      int* p = seedFound;
      for (i = 0; i < 0x17; i = i + 1) {
        if (*p == 0) {
          return '\0';
        }
        p = p + 1;
      }
      return '\x01';
    }
  } while (true);
}

// FUNCTION: IMPERIALISM 0x00526ba0
char TMapMaker::GetBoolSlot28() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00526c20
void TMapMaker::SetControlValue(int value) {}

// FUNCTION: IMPERIALISM 0x00527040
TEventHandler* TMapMaker::QueryStepValue() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00527300
void TMapMaker::DispatchQueuedUiCommandAndRelease(void* payload) {}

// FUNCTION: IMPERIALISM 0x005274d0
void TMapMaker::DispatchEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)commandId;
  (void)sourceHandler;
  (void)event;
}

// FUNCTION: IMPERIALISM 0x005275a0
void TMapMaker::DispatchUiSelectionToHandler(void* payload) {}

// FUNCTION: IMPERIALISM 0x00527730
void TMapMaker::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x00527d00
char TMapMaker::vmethod_0023() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00527ed0
char TMapMaker::GetDeactivateVetoCode() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00528140
class TView* TMapMaker::OwnerPanel() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005283c0
void TMapMaker::ForwardParam(int param) {}

// FUNCTION: IMPERIALISM 0x00528670
char TMapMaker::DoIdle(int action) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00528780
int TMapMaker::GetCityDialogValueDword10() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005288a0
void TMapMaker::SetCityDialogValueDword10(int value) {}

// FUNCTION: IMPERIALISM 0x00528ce0
void TMapMaker::DispatchCityProductionAction1A() {}

// FUNCTION: IMPERIALISM 0x00528e50
void TMapMaker::vmethod_0017(int param) {}

// FUNCTION: IMPERIALISM 0x005292f0
void TMapMaker::DispatchCityProductionAction1B() {}

// FUNCTION: IMPERIALISM 0x005296a0
char TMapMaker::ActivateCityProductionViewIfAllowed() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005297e0
char TMapMaker::TryDeactivateActiveView() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005298a0
int TMapMaker::GetFineGridCellBasePointerFromCoarseIndex(int coarseIndex) {
  int cell =
      (static_cast<short>(coarseIndex % 0x1b) + static_cast<short>(coarseIndex / 0x1b) * 0x6c) *
          0x90 +
      reinterpret_cast<int>(mapTileGrid08);
  if ((coarseIndex / 0x1b & 1U) != 0) {
    cell = cell + -0x48;
  }
  return cell;
}

// FUNCTION: IMPERIALISM 0x00529f60
void TMapMaker::OnDeactivated() {}

// FUNCTION: IMPERIALISM 0x0052a670
int TMapMaker::GetCityRegionIdAtTileIndex(int tileIndex) {
  if (tileIndex >= 0) {
    char* tile = mapTileGrid08 + tileIndex * 0x24;
    if (*tile == '\x05') {
      return tile[4] - 0x17;
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x0052e840
void TMapMaker::OnDeactivateVetoed(int gate) {}

// FUNCTION: IMPERIALISM 0x0052e890
void TMapMaker::DispatchUiCommand19ToParent() {}

// FUNCTION: IMPERIALISM 0x0052e900
void TMapMaker::HandleCityProductionNoOp() {}
