#include "RuntimeGameSnapshot.h"

#include "RuntimeRegistry.h"
#include "RuntimeRun.h"

#include "game/globals/game_session_globals.h"
#include "game/globals/map_globals.h"
#include "game/map/TMapMgr.h"
#include "game/ui_screens/TSimMgr.h"

// VC5 libcmt rand.obj stores the thread-local LCG state at +0x14 in the block returned
// by _getptd. This test-only observation is backed by the vendored rand.obj disassembly;
// production source continues to use the ordinary CRT rand/srand API.
extern "C" void* __cdecl _getptd(void);

namespace {

unsigned int RuntimeFnv1a(const CString& value) {
  unsigned int hash = 2166136261U;
  const unsigned char* bytes =
      static_cast<const unsigned char*>(static_cast<const void*>(static_cast<LPCSTR>(value)));
  for (int index = 0; index < value.GetLength(); ++index) {
    hash ^= bytes[index];
    hash *= 16777619U;
  }
  return hash;
}

CString RuntimeHashText(const CString& value) {
  CString text;
  text.Format("%08x", RuntimeFnv1a(value));
  return text;
}

unsigned int RuntimeCrtRandState() {
  struct CrtThreadDataPrefix {
    unsigned char prefix00[0x14];
    unsigned int randState14;
  };
  CrtThreadDataPrefix* threadData = static_cast<CrtThreadDataPrefix*>(_getptd());
  return threadData != 0 ? threadData->randState14 : 0;
}

CString CaptureMetadata(const RuntimeRun& run) {
  CString json;
  json.Format("{\"scenario_map_index_plus_one\":%d,\"economic_turn\":%d,\"turn_state\":%d,"
              "\"mode\":%d,\"difficulty\":%d,\"active_nation\":%d,\"selected_nation\":%d}",
              g_pSimMgr != 0 ? g_pSimMgr->scenarioMapIndexPlusOne : 0,
              g_pSimMgr != 0 ? g_pSimMgr->economicTurn : -1,
              g_pSimMgr != 0 ? g_pSimMgr->turnStateCode : -1, g_pSimMgr != 0 ? g_pSimMgr->mode : -1,
              g_pSimMgr != 0 ? g_pSimMgr->difficultyLevel : -1,
              g_pSimMgr != 0 ? g_pSimMgr->activeNationSlot : -1, run.SelectedNationSlot());
  return json;
}

CString CaptureRng(const RuntimeRun& run) {
  CString json;
  json.Format("{\"runtime_seed\":%u,\"crt_rand_state\":%u,\"map_generation_lcg\":%u,"
              "\"zone_status_lcg\":%u}",
              run.Seed(), RuntimeCrtRandState(), g_mapGenLcgState_006a38e8,
              g_zoneStatusCodePrngSeed_006a5aec);
  return json;
}

CString CaptureWorld() {
  CString json;
  json.Format("{\"width\":108,\"height\":60,\"wrap\":%d,\"tiles\":[",
              g_pGlobalMapState->hexNeighborWrapHorizontally);
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    CString row;
    row.Format(
        "%s[%d,%d,%d,%d,%d,%d,%d,%u,%d,%u]", tileIndex == 0 ? "" : ",",
        static_cast<int>(tile.GetTerrainKind()), static_cast<int>(tile.ownerNationTag04),
        static_cast<int>(tile.formerOwnerNationTag03), static_cast<int>(tile.cityRecordIndex),
        static_cast<int>(tile.developmentClassNibbles0c),
        static_cast<int>(tile.resourceTypeByEdge[0]), static_cast<int>(tile.resourceTypeByEdge[1]),
        static_cast<unsigned int>(tile.railFlags17), static_cast<int>(tile.tileActionState16),
        static_cast<unsigned int>(tile.activeFlags1c));
    json += row;
  }
  json += "]}";
  return json;
}

} // namespace

void CaptureRuntimeGameSnapshot(RuntimeRun& run) {
  if (!run.CapturesSnapshot(kRuntimeSnapshotGame) || !run.GameSnapshotJson().IsEmpty() ||
      g_pGlobalMapState == 0 || g_pGlobalMapState->terrainStateTable == 0 || g_pSimMgr == 0) {
    return;
  }

  CString metadata(CaptureMetadata(run));
  CString rng(CaptureRng(run));
  CString world(CaptureWorld());
  CString state(metadata);
  state += rng;
  state += world;
  CString metadataHash(RuntimeHashText(metadata));
  CString rngHash(RuntimeHashText(rng));
  CString worldHash(RuntimeHashText(world));
  CString stateHash(RuntimeHashText(state));

  run.GameSnapshotJson().Format("{\"schema\":\"imperialism.game_snapshot.v1\","
                                "\"sections\":[\"metadata\",\"rng\",\"world\"],"
                                "\"hashes\":{\"metadata\":\"%s\",\"rng\":\"%s\",\"world\":\"%s\","
                                "\"state\":\"%s\"},\"metadata\":%s,\"rng\":%s,\"world\":%s}",
                                static_cast<LPCSTR>(metadataHash), static_cast<LPCSTR>(rngHash),
                                static_cast<LPCSTR>(worldHash), static_cast<LPCSTR>(stateHash),
                                static_cast<LPCSTR>(metadata), static_cast<LPCSTR>(rng),
                                static_cast<LPCSTR>(world));
}
