#include "UnitChainProbe.h"

#include "game/core/global_data_tables.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/military/TCivUnit.h"
#include "game/military/TMilitaryUnit.h"
#include "game/pointer_representation.h"

namespace {

enum { kProvinceRecordCount = 0x180, kMapTileCount = 0x1950 };

// No unit chain in a real game is anywhere near this long; a longer walk means a cycle.
enum { kMaxChainLength = 4096 };

// The lowest address a heap object can live at under Win32. Anything below it in a pointer slot is
// not an address -- it is some other field's value written through the wrong offset, which is the
// corruption this probe exists to name rather than dereference.
const unsigned long kLowestPlausibleObjectAddress = 0x00010000;

bool IsPointerShaped(const void* candidate) {
  unsigned long address = PointerAddressLong32(candidate);
  // Objects are at least int-aligned; an odd value is never one.
  return address >= kLowestPlausibleObjectAddress && (address & 1) == 0;
}

// Walks one chain, reporting the first node that cannot be followed. `head` is checked before it is
// dereferenced, so a corrupt head is named rather than followed.
bool ChainIsWalkable(TUnit* head, CString* detail) {
  int length = 0;
  TUnit* node = head;
  while (node != 0) {
    if (!IsPointerShaped(node)) {
      detail->Format("node %d is not a pointer (0x%08lx)", length, PointerAddressLong32(node));
      return false;
    }
    if (++length > kMaxChainLength) {
      detail->Format("chain did not terminate within %d nodes", static_cast<int>(kMaxChainLength));
      return false;
    }
    TUnit* next = node->nextAtLocation14;
    if (next != 0 && !IsPointerShaped(next)) {
      detail->Format("node %d's next link is not a pointer (0x%08lx)", length - 1,
                     PointerAddressLong32(next));
      return false;
    }
    node = next;
  }
  return true;
}

} // namespace

RuntimeActionResult UnitChainProbe::VerifyChainsAreWalkable(const char* stage) {
  if (g_pGlobalMapState == 0) {
    return RuntimeActionResult::Success();
  }
  CString detail;
  for (int province = 0; province < kProvinceRecordCount; ++province) {
    if (!ChainIsWalkable(g_pGlobalMapState->cityScoreTable[province].stationedUnitChain98,
                         &detail)) {
      CString message;
      message.Format("%s left province %d's stationed-unit chain unwalkable: %s", stage, province,
                     static_cast<LPCSTR>(detail));
      return RuntimeActionResult::Failure(message);
    }
  }
  for (int tile = 0; tile < kMapTileCount; ++tile) {
    if (!ChainIsWalkable(g_pGlobalMapState->terrainStateTable[tile].firstCivilianOrder20,
                         &detail)) {
      CString message;
      message.Format("%s left tile %d's civilian-order chain unwalkable: %s", stage, tile,
                     static_cast<LPCSTR>(detail));
      return RuntimeActionResult::Failure(message);
    }
  }
  return RuntimeActionResult::Success();
}
