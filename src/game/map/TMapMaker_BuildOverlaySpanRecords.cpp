// TMapMaker overlay-segment builder: match the per-tile-edge Seapoint quad records
// (g_seapointQuadTable_006a3478) into region-border SeaSegments
// (g_regionBorderLinkTable_006a3900) that MergeSmallCityRegionsAndCompactIds later consumes.
//
// Isolated in its own translation unit so its size/codegen does not perturb the register
// allocation of the neighbouring stretch methods in sea_geometry.cpp.

#include "game/map/sea_geometry.h"

#include <math.h>
#include <stdlib.h>

#include "decomp_types.h"
#include "game/map_ui/TMapMaker.h"
#include "game/globals/prelude.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"

// A body this size exhausts VC5's inline budget: retail expands
// stretch<Seapoint>::operator[] only at the first few sites and calls the out-of-line copy
// at the rest (see the big-functions skill). Suspending automatic expansion for this one
// function reproduces the majority case; the handful of early sites retail did inline are
// the residual.
#pragma inline_depth(0)
// FUNCTION: IMPERIALISM 0x0052cae0
void TMapMaker::BuildOverlaySpanRecordsFromQuadBorderLinks() {
  SeaSegmentStretch& seg = g_regionBorderLinkTable_006a3900;
  SeapointStretch& quad = g_seapointQuadTable_006a3478;

  // Reset the output segment table.
  if (seg.data != nullptr) {
    free(seg.Detach());
  }

  unsigned int i = 0;
  if (quad.count == 0) {
    return;
  }
  do {
    unsigned char isInvalid = quad[i].coord00 == -1;
    if (isInvalid) {
      i = i + 1;
      continue;
    }
    quad[i];
    quad[i];
    unsigned int j = i + 1;
    unsigned int bestPrimary = 0xffffffff;
    unsigned int bestSecondary = 0xffffffff;
    if (j < static_cast<unsigned int>(quad.count)) {
      do {
        Seapoint* a = &quad[i];
        Seapoint* b = &quad[j];
        unsigned char sameEdge = a->lo04 == b->lo04 && a->hi08 == b->hi08;
        if (sameEdge) {
          int dirDelta = ((b->f0c - a->f0c) + 6) % 6;
          unsigned char isPrimaryDirection = dirDelta >= 2 && dirDelta <= 4;
          if (isPrimaryDirection) {
            if (bestPrimary != 0xffffffff) {
              Seapoint* pa = &quad[i];
              Seapoint* pb = &quad[j];
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
              if ((&quad[bestPrimary])->WrappedDeltaMetric((&quad[i])) <= candidateDist) {
                goto next;
              }
            }
            bestPrimary = j;
          } else if (bestPrimary == 0xffffffff) {
            if (bestSecondary != 0xffffffff) {
              float candidateDist = static_cast<float>((&quad[j])->WrappedDeltaMetric((&quad[i])));
              if ((&quad[bestSecondary])->WrappedDeltaMetric((&quad[i])) <= candidateDist) {
                goto next;
              }
            }
            bestSecondary = j;
          }
        }
      next:
        j = j + 1;
      } while (j < static_cast<unsigned int>(quad.count));
    }
    if (bestPrimary == 0xffffffff) {
      bestPrimary = bestSecondary;
    }
    if (bestPrimary == 0xffffffff) {
      Seapoint* p = (&quad[i]);
      p->coord00 = -1;
      p->hi08 = -1;
      p->lo04 = -1;
    } else {
      SeaSegment tmp;
      tmp.InitFromPoints((&quad[bestPrimary]), (&quad[i]));
      stretch<SeaSegment>* out = &seg;
      out->Add(tmp);
      Seapoint* pi = (&quad[i]);
      pi->coord00 = -1;
      pi->hi08 = -1;
      pi->lo04 = -1;
      Seapoint* pm = (&quad[bestPrimary]);
      pm->coord00 = -1;
      pm->hi08 = -1;
      pm->lo04 = -1;
    }
  } while (i < static_cast<unsigned int>(quad.count));
}
#pragma inline_depth()
