// TMapMaker::AssignRegionIdsToUnclaimedBorderSegmentSides, isolated in its own translation
// unit: folding it into sea_geometry.cpp perturbed that TU's register allocation and flipped
// the sort branch in EmitOverlaySegmentFromTileEdgeSorted (the TU-codegen fragility the
// big-functions skill warns about).

#include "game/map/sea_geometry.h"

#include "decomp_types.h"
#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/map_ui/TMapMaker.h"

// FUNCTION: IMPERIALISM 0x0052b820
void TMapMaker::AssignRegionIdsToUnclaimedBorderSegmentSides() {
  cityRegionCount2a4 = 0;

  unsigned int index = 0;
  unsigned int count = g_regionBorderLinkTable_006a3900.count;
  if (index < count) {
    do {
      if (g_regionBorderLinkTable_006a3900.At(index)->attr10 == -1) {
        int regionId = cityRegionCount2a4;
        cityRegionCount2a4 = regionId + 1;
        AssignRegionIdAlongBorderSegmentChain(index, '\x01', static_cast<short>(regionId));
        count = g_regionBorderLinkTable_006a3900.count;
      }
      if (g_regionBorderLinkTable_006a3900.At(index)->attr12 == -1) {
        int regionId = cityRegionCount2a4;
        cityRegionCount2a4 = regionId + 1;
        AssignRegionIdAlongBorderSegmentChain(index, '\0', static_cast<short>(regionId));
        count = g_regionBorderLinkTable_006a3900.count;
      }
      index = index + 1;
    } while (index < count);
  }

  // A second pass that only stretches each slot. It has no observable effect once the
  // table is already this long -- whatever the original read here optimized away -- but the
  // stretch sequence is still emitted, so the loop is kept.
  index = 0;
  if (index < count) {
    do {
      g_regionBorderLinkTable_006a3900[index];
      index = index + 1;
    } while (index < static_cast<unsigned int>(g_regionBorderLinkTable_006a3900.count));
  }
}
