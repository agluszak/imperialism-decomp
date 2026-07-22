// TMapMaker overlay-segment builder: match the per-tile-edge Seapoint quad records
// (g_seapointQuadTable_006a3478) into region-border SeaSegments
// (g_regionBorderLinkTable_006a3900) that MergeSmallCityRegionsAndCompactIds later consumes.
//
// Isolated in its own translation unit so its size/codegen does not perturb the register
// allocation of the neighbouring stretch methods in sea_geometry.cpp.

#include "game/sea_geometry.h"

#include <math.h>
#include <stdlib.h>

#include "decomp_types.h"
#include "game/TMapMaker.h"
#include "game/global_data_tables.h"

namespace {

// Inline "ensure-and-address" accessor for the overlay-quad table, matching the original's
// inlined grow-on-demand element access (the grow itself is the real OverStretch call). Used
// for the comparison reads; the metric/build/invalidate sites go through operator[] instead.
inline Seapoint* QuadEnsureAt(unsigned int index) {
  SeapointStretch& t = g_seapointQuadTable_006a3478;
  if (index >= static_cast<unsigned int>(t.Capacity())) {
    t.OverStretch(index + 1);
  }
  if (index >= static_cast<unsigned int>(t.Count())) {
    t.Count() = index + 1;
  }
  return t.Data() + index;
}

} // namespace

// FUNCTION: IMPERIALISM 0x0052cae0
void TMapMaker::BuildOverlaySpanRecordsFromQuadBorderLinks() {
  SeaSegmentStretch& seg = g_regionBorderLinkTable_006a3900;
  SeapointStretch& quad = g_seapointQuadTable_006a3478;

  // Reset the output segment table.
  if (seg.Data() != nullptr) {
    free(seg.Detach());
  }

  unsigned int i = 0;
  if (quad.Count() == 0) {
    return;
  }
  do {
    if (QuadEnsureAt(i)->coord00 == -1) {
      i = i + 1;
      continue;
    }
    QuadEnsureAt(i);
    QuadEnsureAt(i);
    unsigned int j = i + 1;
    unsigned int bestPrimary = 0xffffffff;
    unsigned int bestSecondary = 0xffffffff;
    if (j < static_cast<unsigned int>(quad.Count())) {
      do {
        Seapoint* a = QuadEnsureAt(i);
        Seapoint* b = QuadEnsureAt(j);
        if (a->lo04 == b->lo04 && a->hi08 == b->hi08) {
          int dirDelta = ((b->f0c - a->f0c) + 6) % 6;
          if (dirDelta >= 2 && dirDelta <= 4) {
            if (bestPrimary != 0xffffffff) {
              Seapoint* pa = QuadEnsureAt(i);
              Seapoint* pb = QuadEnsureAt(j);
              int rowDelta = pa->coord00 / 0xd8 - pb->coord00 / 0xd8;
              if (rowDelta < 0) {
                rowDelta = -rowDelta;
              }
              int colDelta = ((pa->coord00 % 0xd8 - pb->coord00 % 0xd8) + 0xd8) % 0xd8;
              if (0x6c < colDelta) {
                colDelta = 0xd7 - colDelta;
              }
              float candidateDist = static_cast<float>(
                  sqrt(static_cast<double>(colDelta * colDelta * rowDelta * rowDelta)));
              if (quad[bestPrimary]->WrappedDeltaMetric(quad[i]) <= candidateDist) {
                goto next;
              }
            }
            bestPrimary = j;
          } else if (bestPrimary == 0xffffffff) {
            if (bestSecondary != 0xffffffff) {
              float candidateDist = static_cast<float>(quad[j]->WrappedDeltaMetric(quad[i]));
              if (quad[bestSecondary]->WrappedDeltaMetric(quad[i]) <= candidateDist) {
                goto next;
              }
            }
            bestSecondary = j;
          }
        }
      next:
        j = j + 1;
      } while (j < static_cast<unsigned int>(quad.Count()));
    }
    if (bestPrimary == 0xffffffff) {
      bestPrimary = bestSecondary;
    }
    if (bestPrimary == 0xffffffff) {
      Seapoint* p = quad[i];
      p->coord00 = -1;
      p->hi08 = -1;
      p->lo04 = -1;
    } else {
      SeaSegment tmp;
      tmp.InitFromPoints(quad[bestPrimary], quad[i]);
      stretch<SeaSegment, SeaSegmentTag>* out = &seg;
      out->Add(tmp);
      Seapoint* pi = quad[i];
      pi->coord00 = -1;
      pi->hi08 = -1;
      pi->lo04 = -1;
      Seapoint* pm = quad[bestPrimary];
      pm->coord00 = -1;
      pm->hi08 = -1;
      pm->lo04 = -1;
    }
  } while (i < static_cast<unsigned int>(quad.Count()));
}
