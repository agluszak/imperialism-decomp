// SeapointStretch / SeaSegmentStretch -- two concrete instantiations of the project-local
// stretch<T> growable-array family used by the UMapper coastline/region builder.
//
// The single vtable slot of each (Add) is the by-value append; it was
// previously mis-attributed to TMapMaker (SetEnabled/SetState) because Ghidra merged the
// two adjacent single-slot vtables into TMapMaker's. See sea_geometry.h.

#include "game/map/sea_geometry.h"

#include <math.h>

#include "decomp_types.h"
#include "game/map/TMapMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"

namespace {

// Segment heading angle scale (original double at 0x006598d8): atan2(dy,dx) is scaled into
// the 16-bit angle stored in SeaSegment::angle14. Referenced by both InitFromPoints and
// RecomputeEndpointsAndAngle, matching the single shared constant in the original.
const double kSeaAngleScale = 11733.857334728455;

} // namespace

// Functions are emitted in ascending original-address order (decomplint requirement), so
// the Seapoint/SeaSegment record methods interleave with the two stretch arrays' methods.

// TEMPLATE: IMPERIALISM 0x0052a760
// ?Add@?$stretch@USeaSegment@@@@UAEPAUSeaSegment@@U2@@Z

// FUNCTION: IMPERIALISM 0x0052ab00
void SeaSegment::RecomputeEndpointsAndAngle() {
  if (y1 < y0 || (y0 == y1 && x1 < x0)) {
    short nx0 = x1;
    short ny0 = y1;
    short nx1 = x0;
    short ny1 = y0;
    x0 = nx0;
    y0 = ny0;
    x1 = nx1;
    y1 = ny1;
    coord0 = x0 + y0 * 0xd8;
    coord1 = x1 + y1 * 0xd8;
  }
  int adx = x0 - x1;
  wrap16 = (adx < 0 ? -adx : adx) > 0x6c;
  int dx;
  int dy;
  if (wrap16 && x0 < x1) {
    dx = (x1 - x0) - 0xd8;
    dy = y1 - y0;
  } else {
    dx = x1 - x0;
    dy = y1 - y0;
  }
  angle14 = static_cast<short>(
      static_cast<int>(atan2(static_cast<double>(dy), static_cast<double>(dx)) * kSeaAngleScale));
}

// FUNCTION: IMPERIALISM 0x0052b1e0
void Seapoint::InitSorted(int value, int a, int b, int extra) {
  coord00 = value;
  f0c = extra;
  lo04 = a;
  hi08 = b;
  if (a > b) {
    lo04 = b;
    hi08 = a;
  }
}

// FUNCTION: IMPERIALISM 0x0052b220
void SeaSegment::InitFromPoints(const Seapoint* p0, const Seapoint* p1) {
  angle14 = 0;
  int c0 = p0->coord00;
  coord0 = c0;
  coord1 = p1->coord00;
  int c1 = coord1;
  x0 = static_cast<short>(c0 % 0xd8);
  y0 = static_cast<short>(c0 / 0xd8);
  x1 = static_cast<short>(c1 % 0xd8);
  y1 = static_cast<short>(c1 / 0xd8);
  attr10 = static_cast<short>(p0->lo04);
  attr12 = static_cast<short>(p0->hi08);
  if (y1 < y0 || (y0 == y1 && x1 < x0)) {
    short nx0 = x1;
    short ny0 = y1;
    short nx1 = x0;
    short ny1 = y0;
    x0 = nx0;
    y0 = ny0;
    x1 = nx1;
    y1 = ny1;
    coord0 = x0 + y0 * 0xd8;
    coord1 = x1 + y1 * 0xd8;
  }
  int adx = x0 - x1;
  wrap16 = (adx < 0 ? -adx : adx) > 0x6c;
  int dx;
  int dy;
  if (wrap16 && x0 < x1) {
    dx = (x1 - x0) - 0xd8;
    dy = y1 - y0;
  } else {
    dx = x1 - x0;
    dy = y1 - y0;
  }
  angle14 = static_cast<short>(
      static_cast<int>(atan2(static_cast<double>(dy), static_cast<double>(dx)) * kSeaAngleScale));
}

// TEMPLATE: IMPERIALISM 0x0052b3e0
// ?OverStretch@?$stretch@USeaSegment@@@@QAEXI@Z

// TEMPLATE: IMPERIALISM 0x0052b460
// ??A?$stretch@USeaSegment@@@@QAEAAUSeaSegment@@I@Z

// TEMPLATE: IMPERIALISM 0x0052b500
// stretch::Detach

// FUNCTION: IMPERIALISM 0x0052bef0
void SeaSegment::ExtractWrappedEndpoint(int* out, char side) const {
  if (side != '\0') {
    int cx = x0;
    short cy = y0;
    if (g_pGlobalMapState->hexNeighborWrapHorizontally20 == '\0') {
      if (0xd7 < cx) {
        out[0] = cx - 0xd8;
        out[1] = cy;
        return;
      }
      if (cx < 0) {
        cx = cx + 0xd8;
      }
    }
    out[0] = cx;
    out[1] = cy;
    return;
  }
  int cx = x1;
  short cy = y1;
  if (g_pGlobalMapState->hexNeighborWrapHorizontally20 == '\0') {
    if (cx < 0xd8) {
      if (cx < 0) {
        cx = cx + 0xd8;
      }
    } else {
      cx = cx - 0xd8;
    }
  }
  out[0] = cx;
  out[1] = cy;
}

// FUNCTION: IMPERIALISM 0x0052c000
unsigned short SeaSegment::SelectAttrByAngle() const {
  if (static_cast<unsigned short>(angle14) < 0x8fff) {
    return static_cast<unsigned short>(attr12);
  }
  return static_cast<unsigned short>(attr10);
}

// TEMPLATE: IMPERIALISM 0x0052c030
// stretch::At

// --- SeapointStretch (0x10-byte elements) ----------------------------------------------

// TEMPLATE: IMPERIALISM 0x0052c0a0
// ?Add@?$stretch@USeapoint@@@@UAEPAUSeapoint@@U2@@Z

// TEMPLATE: IMPERIALISM 0x0052ca00
// stretch::Detach

// FUNCTION: IMPERIALISM 0x0052ca20
void EmitOverlaySegmentFromTileEdgeSorted(int tileIndex, char side, int a, int b, int extra) {
  unsigned int row = tileIndex / 0x6c;
  int column = (row & 1) + (tileIndex % 0x6c) * 2;
  int overlayX = column;
  if (side == '\0') {
    overlayX = column + 2;
    row = row + 1;
    if (0xd7 < overlayX) {
      overlayX = column - 0xd6;
    }
  }
  int hi = b;
  int lo = a;
  if (b < a) {
    hi = a;
    lo = b;
  }
  Seapoint pt;
  pt.coord00 = overlayX + row * 0xd8;
  pt.lo04 = lo;
  pt.hi08 = hi;
  pt.f0c = extra;
  // Dispatch through the stretch<Seapoint> base so the append goes through the vtable slot
  // (the original calls it indirectly), rather than being devirtualized to a direct call.
  stretch<Seapoint>* table = &g_seapointQuadTable_006a3478;
  table->Add(pt);
}

// FUNCTION: IMPERIALISM 0x0052d030
double Seapoint::WrappedDeltaMetric(const Seapoint* other) const {
  int thisCoordinate = coord00;
  int otherCoordinate = other->coord00;
  int rowDelta = thisCoordinate / 0xd8 - otherCoordinate / 0xd8;
  if (rowDelta < 0) {
    rowDelta = -rowDelta;
  }
  int colDelta = ((thisCoordinate % 0xd8 - otherCoordinate % 0xd8) + 0xd8) % 0xd8;
  if (0x6c < colDelta) {
    colDelta = 0xd7 - colDelta;
  }
  return sqrt(static_cast<double>(colDelta * colDelta * rowDelta * rowDelta));
}

// TEMPLATE: IMPERIALISM 0x0052d0d0
// ?OverStretch@?$stretch@USeapoint@@@@QAEXI@Z

// TEMPLATE: IMPERIALISM 0x0052d150
// ??A?$stretch@USeapoint@@@@QAEAAUSeapoint@@I@Z

// TEMPLATE: IMPERIALISM 0x0052e310
// stretch::SetCapacity
