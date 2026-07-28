// TMapMaker::RebuildUMapperRouteRecordsAndActiveMapRects (0x0052e350) -- the UMapper.cpp pass
// that turns the region-border SeaSegment table (g_regionBorderLinkTable_006a3900) into the
// map-order route buffer and active map-action contexts. It first drops degenerate links
// (attr10 == attr12), counting the live ones; allocates one CRect route record per live link
// in the map-order singleton's route buffer; wires mutual primary-neighbour adjacency between
// the two region contexts a link connects; then refreshes port-zone adjacency and zone status
// codes. Own translation unit (TMapMaker map-generation split).

#include "game/map_generation/TMapMaker.h"

#include "decomp_types.h"
#include "game/navy/TOcean.h"
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/map/sea_geometry.h"
#include "game/gfx/ui_invalidation_guard.h"

namespace {
const char kUMapperPath[] = "D:\\Ambit\\Cross\\UMapper.cpp";

// The original inlines the stretch's bounds-checked accessor (index < count ? &data[i] : null)
// at every touch of the border-link table, so reproduce it as a file-local inline helper.
inline SeaSegment* LinkAt(unsigned int index) {
  SeaSegmentStretch& links = g_regionBorderLinkTable_006a3900;
  return links.At(index);
}

inline bool LinkIsEmpty(const SeaSegment* rec) {
  return rec->x0 == rec->x1 && rec->y0 == rec->y1;
}

// Inlined SeaSegmentStretch::operator[] body: grow to hold `index`, extend the count, and
// hand back the element pointer. The original inlines exactly this (calling OverStretch for
// the grow) at the mutating access sites.
inline SeaSegment* LinkReserve(unsigned int index) {
  SeaSegmentStretch& links = g_regionBorderLinkTable_006a3900;
  return &links[index];
}
} // namespace

// FUNCTION: IMPERIALISM 0x0052e350
void TMapMaker::RebuildUMapperRouteRecordsAndActiveMapRects() {
  SeaSegmentStretch& links = g_regionBorderLinkTable_006a3900;

  // --- Pass 1: collapse degenerate links, count the live ones ---
  int liveCount = 0;
  unsigned int i = 0;
  for (i = 0; i < static_cast<unsigned int>(links.Count()); ++i) {
    if (LinkAt(i)->attr10 == LinkAt(i)->attr12) {
      SeaSegment* rec = LinkAt(i);
      rec->attr12 = -1;
      rec->y1 = 0;
      rec->y0 = 0;
      rec->x1 = 0;
      rec->x0 = 0;
      rec->attr10 = -1;
      rec->coord1 = -1;
      rec->coord0 = -1;
    }
    if (!LinkIsEmpty(LinkAt(i))) {
      liveCount = liveCount + 1;
    }
  }

  g_pActiveMapOrderContext->AllocateRouteNodeStateBufferByCount(static_cast<short>(liveCount));

  // --- Pass 2: emit a CRect route record per live link ---
  short routeIndex = 0;
  for (i = 0; i < static_cast<unsigned int>(links.Count()); ++i) {
    if (!LinkIsEmpty(LinkAt(i))) {
      if (LinkAt(i)->attr10 == -1 || LinkAt(i)->attr12 == -1) {
        if (g_bOverlayRouteRebuildAssertSuppressed == 0) {
          TemporarilyClearAndRestoreUiInvalidationFlag(kUMapperPath, 0x128f);
        }
      }
    }
    if (!LinkIsEmpty(LinkAt(i))) {
      SeaSegment* rec = LinkReserve(i);
      CRect rect(rec->x0, rec->y0, rec->x1, rec->y1);
      g_pActiveMapOrderContext->routeSegments[routeIndex] = rect;
      routeIndex = routeIndex + 1;
    }
  }

  g_pActiveMapOrderContext->InitializeMapActionContextsForNationCountUsingCostField(
      cityRegionCount2a4);

  // --- Pass 3: wire mutual primary-neighbour adjacency between each link's two contexts ---
  int k = 0;
  for (k = 0; k < links.Count(); ++k) {
    if (LinkIsEmpty(LinkAt(k))) {
      continue;
    }
    LinkReserve(k);
    SeaSegment* rec = LinkReserve(k);
    TZone* contextHi = g_pActiveMapOrderContext->GetMapActionContextEntryByIndex(rec->attr12);
    TZone* contextLo = g_pActiveMapOrderContext->GetMapActionContextEntryByIndex(rec->attr10);
    contextLo->AppendUniquePrimaryNeighbor(contextHi);
    TZone* backLo = g_pActiveMapOrderContext->GetMapActionContextEntryByIndex(
        links[static_cast<unsigned int>(k)].attr10);
    TZone* backHi = g_pActiveMapOrderContext->GetMapActionContextEntryByIndex(
        links[static_cast<unsigned int>(k)].attr12);
    backHi->AppendUniquePrimaryNeighbor(backLo);
  }

  PopulatePortZoneAdjacencyToNearbyCityContexts();
  RegenerateAllMapActionContextStatusCodes();
}
