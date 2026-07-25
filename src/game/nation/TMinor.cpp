#include "game/nation/TMinor.h"
#include "game/resource_domain_types.h"
#include "game/core/stream_byteswap.h"

#include <stdlib.h>

#include "game/ui_core/CIterator.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/military/TArmyMgr.h"
#include "game/military/TCivUnit.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/map/TMapMgr.h"
#include "game/navy/TOcean.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/city_ui/TLongintList.h"
#include "game/core/TStream.h"
#include "game/ui_widgets/TTown.h"
#include "game/military/TUnit.h"
#include "game/nation_stream_serialization.h"

#include <new>

static const unsigned int kAddrClassDescTMinor = 0x006536a0;

namespace {

short DecodeTerrainNationSlotFromEncoded(short encodedNationSlot, short nationSlot) {
  if (encodedNationSlot < 200) {
    if (encodedNationSlot < 100) {
      return nationSlot;
    }
    return static_cast<short>(encodedNationSlot - 100);
  }
  return static_cast<short>(encodedNationSlot - 200);
}

int SignedDivideBy100(int value) {
  return value / 100;
}

} // namespace

// SYNTHETIC: IMPERIALISM 0x004e3660
// TMinor::CreateObject
// SYNTHETIC: IMPERIALISM 0x004e36f0
// TMinor::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMinor, TCountry)

void* TMinor::GetTMinorClassNamePointer() {
  return reinterpret_cast<void*>(kAddrClassDescTMinor);
}

// FUNCTION: IMPERIALISM 0x004e3710
TMinor::TMinor() {}

// SYNTHETIC: IMPERIALISM 0x004e3790
// TMinor::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004e3830
void TMinor::IMinor(NationSlot nationSlot) {
  // Constructed and destroyed unused in the original (EH state 0) -- kept for the
  // matching EH frame.
  CString unusedText;
  InitializeNationStateIdentityAndOwnedRegionList(nationSlot);

  diplomacyPolicyGate130 = 0;
  diplomacyPolicyPredicateCode12c = -10;
  diplomacyPolicyPredicateCode12e = -10;
  diplomacyPolicyGate132 = 0;
  int i;
  for (i = 0; i < 0x17; ++i) {
    diplomacyPolicyByNation[i] = 0;
    diplomacyGrantByNation[i] = 0;
    needCurrentByType[i] = 0;
    diplomacySaveExt13c[i] = 0;
    recurringGrantByResource[i] = 0;
    memset(&statusRows[i], 0, sizeof(TMinorRuntimeStatusEntry));
  }

  // Recount the need tables from the map: every non-depleted resource edge on a tile
  // this nation owns bumps the per-type counters.
  int tileCount;
  int tileIndex = 0;
  for (tileCount = 0x1950; tileCount != 0; --tileCount) {
    if (g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04 == this->nationSlot) {
      int edgeCount;
      int edge = 0;
      for (edgeCount = 2; edgeCount != 0; --edgeCount) {
        int resourceType = static_cast<char>(
            g_pGlobalMapState->terrainStateTable[tileIndex].resourceTypeByEdge[edge]);
        if (g_pGlobalMapState->terrainStateTable[tileIndex].gateFlag != 0xf && resourceType != -1) {
          ++needCurrentByType[resourceType];
          ++diplomacySaveExt13c[resourceType];
        }
        ++edge;
      }
    }
    ++tileIndex;
  }

  if (g_bMultiplayerScenarioSetupActive == 0) {
    bool noImmediateDispatch = IsRemote() == 0;
    if (noImmediateDispatch || g_pSimMgr->scenarioMapIndexPlusOne != 0) {
      TLongintList* candidateTiles = new TLongintList();
      short selectedTile = -1;
      short tile;
      for (tile = 0; tile < 0x1950; ++tile) {
        if (g_pGlobalMapState->terrainStateTable[tile].ownerNationTag04 == nationSlot) {
          TTerrainStateRecordView* record = &g_pGlobalMapState->terrainStateTable[tile];
          if (record->activeFlags1c & 1) {
            selectedTile = tile;
          }
          if (g_pGlobalMapState->IsValidSecondaryNationHomeTileCandidate(tile)) {
            candidateTiles->InsertLast(tile);
          }
        }
      }
      if (selectedTile == -1) {
        int candidateCount = candidateTiles->GetSize();
        // LIBRARY: rand (0x005e83f0)
        selectedTile = static_cast<short>(candidateTiles->At(rand() % candidateCount + 1));
      }
      // Constructed and destroyed unused in the original (EH states 1/2).
      CString unusedTextA;
      CString unusedTextB;
      g_pGlobalMapState->ResetTileToBaseTransportFlag(selectedTile);
      homeTileIndex = selectedTile;
      if (candidateTiles != 0) {
        candidateTiles->Free();
      }
      g_pActiveMapOrderContext->EnsurePortZoneForTile(static_cast<short>(homeTileIndex));
    }
  }

  needCurrentByType[7] = 5;
  switch (nationSlot) {
  case 7:
    diplomacyRandomThreshold11e = 0x44c;
    diplomacyRandomThreshold120 = 0x23a;
    diplomacyRandomThreshold122 = 0xc3;
    diplomacyRandomThreshold124 = 0x5a;
    diplomacyRandomThreshold126 = 0x69;
    diplomacyRandomThreshold128 = 0x8a;
    diplomacyRandomThreshold12a = 0x90;
    diplomacySaveFields134[0] = 7;
    diplomacySaveFields134[1] = 8;
    diplomacySaveFields134[2] = 9;
    diplomacySaveFields134[3] = 0xa;
    break;
  case 8:
    diplomacyRandomThreshold11e = 0x47e;
    diplomacyRandomThreshold120 = 0x249;
    diplomacyRandomThreshold122 = 0xaf;
    diplomacyRandomThreshold124 = 0x52;
    diplomacyRandomThreshold126 = 0x75;
    diplomacyRandomThreshold128 = 0x72;
    diplomacyRandomThreshold12a = 0x84;
    diplomacySaveFields134[0] = 7;
    diplomacySaveFields134[1] = 8;
    diplomacySaveFields134[2] = 9;
    diplomacySaveFields134[3] = 0xa;
    break;
  case 9:
    diplomacyRandomThreshold11e = 0x4b0;
    diplomacyRandomThreshold120 = 0x258;
    diplomacyRandomThreshold122 = 0x9b;
    diplomacyRandomThreshold124 = 0x4a;
    diplomacyRandomThreshold126 = 0x81;
    diplomacyRandomThreshold128 = 0x7e;
    diplomacyRandomThreshold12a = 0x78;
    diplomacySaveFields134[0] = 7;
    diplomacySaveFields134[1] = 8;
    diplomacySaveFields134[2] = 9;
    diplomacySaveFields134[3] = 0xa;
    break;
  case 10:
    diplomacyRandomThreshold11e = 0x4e2;
    diplomacyRandomThreshold120 = 0x267;
    diplomacyRandomThreshold122 = 0x87;
    diplomacyRandomThreshold124 = 0x42;
    diplomacyRandomThreshold126 = 0x8d;
    diplomacyRandomThreshold128 = 0x90;
    diplomacyRandomThreshold12a = 0x6f;
    diplomacySaveFields134[0] = 7;
    diplomacySaveFields134[1] = 8;
    diplomacySaveFields134[2] = 9;
    diplomacySaveFields134[3] = 0xa;
    break;
  case 11:
    diplomacyRandomThreshold11e = 0x514;
    diplomacyRandomThreshold120 = 0x276;
    diplomacyRandomThreshold122 = 0xbe;
    diplomacyRandomThreshold124 = 0x58;
    diplomacyRandomThreshold126 = 0x6c;
    diplomacyRandomThreshold128 = 0x8d;
    diplomacyRandomThreshold12a = 0x93;
    diplomacySaveFields134[0] = 0xb;
    diplomacySaveFields134[1] = 0xc;
    diplomacySaveFields134[2] = 0xd;
    diplomacySaveFields134[3] = 0xe;
    break;
  case 12:
    diplomacyRandomThreshold11e = 0x546;
    diplomacyRandomThreshold120 = 0x285;
    diplomacyRandomThreshold122 = 0xaa;
    diplomacyRandomThreshold124 = 0x50;
    diplomacyRandomThreshold126 = 0x78;
    diplomacyRandomThreshold128 = 0x69;
    diplomacyRandomThreshold12a = 0x87;
    diplomacySaveFields134[0] = 0xb;
    diplomacySaveFields134[1] = 0xc;
    diplomacySaveFields134[2] = 0xd;
    diplomacySaveFields134[3] = 0xe;
    break;
  case 13:
    diplomacyRandomThreshold11e = 0x578;
    diplomacyRandomThreshold120 = 0x294;
    diplomacyRandomThreshold122 = 0x96;
    diplomacyRandomThreshold124 = 0x48;
    diplomacyRandomThreshold126 = 0x84;
    diplomacyRandomThreshold128 = 0x7b;
    diplomacyRandomThreshold12a = 0x75;
    diplomacySaveFields134[0] = 0xb;
    diplomacySaveFields134[1] = 0xc;
    diplomacySaveFields134[2] = 0xd;
    diplomacySaveFields134[3] = 0xe;
    break;
  case 14:
    diplomacyRandomThreshold11e = 0x5aa;
    diplomacyRandomThreshold120 = 0x2a3;
    diplomacyRandomThreshold122 = 0x82;
    diplomacyRandomThreshold124 = 0x40;
    diplomacyRandomThreshold126 = 0x90;
    diplomacyRandomThreshold128 = 0x81;
    diplomacyRandomThreshold12a = 0x72;
    diplomacySaveFields134[0] = 0xb;
    diplomacySaveFields134[1] = 0xc;
    diplomacySaveFields134[2] = 0xd;
    diplomacySaveFields134[3] = 0xe;
    break;
  case 15:
    diplomacyRandomThreshold11e = 0x5dc;
    diplomacyRandomThreshold120 = 0x2b2;
    diplomacyRandomThreshold122 = 0xb9;
    diplomacyRandomThreshold124 = 0x56;
    diplomacyRandomThreshold126 = 0x6f;
    diplomacyRandomThreshold128 = 0x93;
    diplomacyRandomThreshold12a = 0x96;
    diplomacySaveFields134[0] = 0xf;
    diplomacySaveFields134[1] = 0x10;
    diplomacySaveFields134[2] = 0x11;
    diplomacySaveFields134[3] = 0x12;
    break;
  case 16:
    diplomacyRandomThreshold11e = 0x60e;
    diplomacyRandomThreshold120 = 0x2c1;
    diplomacyRandomThreshold122 = 0xa5;
    diplomacyRandomThreshold124 = 0x4e;
    diplomacyRandomThreshold126 = 0x7b;
    diplomacyRandomThreshold128 = 0x6c;
    diplomacyRandomThreshold12a = 0x8a;
    diplomacySaveFields134[0] = 0xf;
    diplomacySaveFields134[1] = 0x10;
    diplomacySaveFields134[2] = 0x11;
    diplomacySaveFields134[3] = 0x12;
    break;
  case 17:
    diplomacyRandomThreshold11e = 0x640;
    diplomacyRandomThreshold120 = 0x2d0;
    diplomacyRandomThreshold122 = 0x91;
    diplomacyRandomThreshold124 = 0x46;
    diplomacyRandomThreshold126 = 0x87;
    diplomacyRandomThreshold128 = 0x78;
    diplomacyRandomThreshold12a = 0x7e;
    diplomacySaveFields134[0] = 0xf;
    diplomacySaveFields134[1] = 0x10;
    diplomacySaveFields134[2] = 0x11;
    diplomacySaveFields134[3] = 0x12;
    break;
  case 18:
    diplomacyRandomThreshold11e = 0x672;
    diplomacyRandomThreshold120 = 0x2df;
    diplomacyRandomThreshold122 = 0x7d;
    diplomacyRandomThreshold124 = 0x3e;
    diplomacyRandomThreshold126 = 0x93;
    diplomacyRandomThreshold128 = 0x84;
    diplomacyRandomThreshold12a = 0x69;
    diplomacySaveFields134[0] = 0xf;
    diplomacySaveFields134[1] = 0x10;
    diplomacySaveFields134[2] = 0x11;
    diplomacySaveFields134[3] = 0x12;
    break;
  case 19:
    diplomacyRandomThreshold11e = 0x6a4;
    diplomacyRandomThreshold120 = 0x2ee;
    diplomacyRandomThreshold122 = 0xb4;
    diplomacyRandomThreshold124 = 0x54;
    diplomacyRandomThreshold126 = 0x72;
    diplomacyRandomThreshold128 = 0x96;
    diplomacyRandomThreshold12a = 0x8d;
    diplomacySaveFields134[0] = 0x13;
    diplomacySaveFields134[1] = 0x14;
    diplomacySaveFields134[2] = 0x15;
    diplomacySaveFields134[3] = 0x16;
    break;
  case 20:
    diplomacyRandomThreshold11e = 0x6d6;
    diplomacyRandomThreshold120 = 0x2fd;
    diplomacyRandomThreshold122 = 0xa0;
    diplomacyRandomThreshold124 = 0x4c;
    diplomacyRandomThreshold126 = 0x7e;
    diplomacyRandomThreshold128 = 0x6f;
    diplomacyRandomThreshold12a = 0x81;
    diplomacySaveFields134[0] = 0x13;
    diplomacySaveFields134[1] = 0x14;
    diplomacySaveFields134[2] = 0x15;
    diplomacySaveFields134[3] = 0x16;
    break;
  case 21:
    diplomacyRandomThreshold11e = 0x708;
    diplomacyRandomThreshold120 = 0x302;
    diplomacyRandomThreshold122 = 0x8c;
    diplomacyRandomThreshold124 = 0x44;
    diplomacyRandomThreshold126 = 0x8a;
    diplomacyRandomThreshold128 = 0x7b;
    diplomacyRandomThreshold12a = 0x75;
    diplomacySaveFields134[0] = 0x13;
    diplomacySaveFields134[1] = 0x14;
    diplomacySaveFields134[2] = 0x15;
    diplomacySaveFields134[3] = 0x16;
    break;
  case 22:
    diplomacyRandomThreshold11e = 0x73a;
    diplomacyRandomThreshold120 = 0x311;
    diplomacyRandomThreshold122 = 0x78;
    diplomacyRandomThreshold124 = 0x3c;
    diplomacyRandomThreshold126 = 0x96;
    diplomacyRandomThreshold128 = 0x87;
    diplomacyRandomThreshold12a = 0x6c;
    diplomacySaveFields134[0] = 0x13;
    diplomacySaveFields134[1] = 0x14;
    diplomacySaveFields134[2] = 0x15;
    diplomacySaveFields134[3] = 0x16;
    break;
  }
}

// FUNCTION: IMPERIALISM 0x004e41c0
void TMinor::ReadFrom(TStream* stream) {
  TCountry::ReadFrom(stream);
  stream->ReadBytes(this->needCurrentByType, sizeof(this->needCurrentByType));
  SwapShortArrayBytes(this->needCurrentByType, 0x17);
  stream->ReadBytes(this->diplomacyPolicyByNation, sizeof(this->diplomacyPolicyByNation));
  SwapShortArrayBytes(this->diplomacyPolicyByNation, 0x17);
  stream->ReadBytes(this->diplomacyGrantByNation, sizeof(this->diplomacyGrantByNation));
  SwapShortArrayBytes(this->diplomacyGrantByNation, 0x17);
  stream->ReadBytes(&this->diplomacyRandomThreshold11e, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold120, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold122, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold124, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold126, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold128, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold12a, 2);
  stream->ReadBytes(&this->diplomacyPolicyPredicateCode12c, 2);
  stream->ReadBytes(&this->diplomacyPolicyPredicateCode12e, 2);
  stream->ReadBytes(&this->diplomacyPolicyGate130, 2);
  stream->ReadBytes(&this->diplomacyPolicyGate132, 2);
  stream->ReadBytes(diplomacySaveFields134, 8);
  SwapShortArrayBytes(diplomacySaveFields134, 4);
  if (g_nSaveFormatVersion > 0x39) {
    stream->ReadBytes(diplomacySaveExt13c, 0x2e);
    SwapShortArrayBytes(diplomacySaveExt13c, 0x17);
  }
}

// FUNCTION: IMPERIALISM 0x004e4390
void TMinor::WriteTo(TStream* stream) {
  TCountry::WriteTo(stream);
  WriteShortArrayElems(stream, this->needCurrentByType, 0x17);
  WriteShortArrayElems(stream, this->diplomacyPolicyByNation, 0x17);
  WriteShortArrayElems(stream, this->diplomacyGrantByNation, 0x17);
  stream->WriteBytes(&this->diplomacyRandomThreshold11e, 2);
  stream->WriteBytes(&this->diplomacyRandomThreshold120, 2);
  stream->WriteBytes(&this->diplomacyRandomThreshold122, 2);
  stream->WriteBytes(&this->diplomacyRandomThreshold124, 2);
  stream->WriteBytes(&this->diplomacyRandomThreshold126, 2);
  stream->WriteBytes(&this->diplomacyRandomThreshold128, 2);
  stream->WriteBytes(&this->diplomacyRandomThreshold12a, 2);
  stream->WriteBytes(&this->diplomacyPolicyPredicateCode12c, 2);
  stream->WriteBytes(&this->diplomacyPolicyPredicateCode12e, 2);
  stream->WriteBytes(&this->diplomacyPolicyGate130, 2);
  stream->WriteBytes(&this->diplomacyPolicyGate132, 2);
  WriteShortArrayElems(stream, diplomacySaveFields134, 4);
  WriteShortArrayElems(stream, diplomacySaveExt13c, 0x17);
}

// Overrides the base (which is a plain "return false"): true when `arg` matches any of
// the four saved diplomacy nation slots at diplomacySaveFields134[0..3]. The vtable slot
// param is a short (word compares), not the int the base decl formerly used.
// FUNCTION: IMPERIALISM 0x004e45f0
char TMinor::ReturnFalseNationStateCapabilityFlag90(short arg) {
  char result = 0;
  if (arg == diplomacySaveFields134[0] || arg == diplomacySaveFields134[1] ||
      arg == diplomacySaveFields134[2] || arg == diplomacySaveFields134[3]) {
    result = 1;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004e4630
short TMinor::SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) {
  short sum = static_cast<short>(this->needCurrentByType[nationSlot] +
                                 this->diplomacyGrantByNation[nationSlot]);
  if (sum < 0) {
    sum = 0;
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004e4660
short TMinor::GetDiplomacyExternalStateByTarget(short nationSlot) {
  return this->needCurrentByType[nationSlot];
}

// FUNCTION: IMPERIALISM 0x004e4680
short TMinor::QueryNationMetricBySlot7C(short metricSlot) {
  return this->diplomacyPolicyByNation[metricSlot];
}

// FUNCTION: IMPERIALISM 0x004e46a0
void TMinor::RebuildDiplomacyEconomicPressureFromMapState(void) {
  diplomacyPolicyPredicateCode12e = -10;
  diplomacyPolicyGate130 = 0;
  diplomacyPolicyGate132 = 0;
  int i;
  for (i = 0; i < 0x17; ++i) {
    diplomacyPolicyByNation[i] = 0;
    diplomacyGrantByNation[i] = 0;
    diplomacySaveExt13c[i] = 0;
    recurringGrantByResource[i] = 0;
    needCurrentByType[i] = 0;
    memset(&statusRows[i], 0, sizeof(TMinorRuntimeStatusEntry));
  }
  needCurrentByType[7] = 2;

  // Recount from the map: every resource edge on a tile this nation owns feeds the
  // need counters; when a great power also holds the tile (secondaryOwnerNationTag18)
  // the capability-requirement level accrues as recurring grants and per-power rows.
  int tileIndex;
  for (tileIndex = 0; static_cast<short>(tileIndex) < 0x1950; ++tileIndex) {
    if (g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04 == this->nationSlot) {
      short tileGreatPower =
          g_pGlobalMapState->terrainStateTable[tileIndex].secondaryOwnerNationTag18;
      if (tileGreatPower == -1) {
        int edgeCount;
        int edge = 0;
        for (edgeCount = 2; edgeCount != 0; --edgeCount) {
          char resourceType =
              g_pGlobalMapState->terrainStateTable[tileIndex].resourceTypeByEdge[edge];
          if (g_pGlobalMapState->terrainStateTable[tileIndex].gateFlag != 0xf &&
              resourceType != -1) {
            ++needCurrentByType[static_cast<int>(resourceType)];
            ++diplomacySaveExt13c[static_cast<int>(resourceType)];
          }
          ++edge;
        }
      } else {
        int edgeCount;
        int edge = 0;
        for (edgeCount = 2; edgeCount != 0; --edgeCount) {
          char resourceType =
              g_pGlobalMapState->terrainStateTable[tileIndex].resourceTypeByEdge[edge];
          if (resourceType != -1) {
            short yieldLevel =
                static_cast<char>(g_pGlobalMapState->FindResourceCapabilityRequirementLevelByType(
                    static_cast<short>(tileIndex), resourceType));
            recurringGrantByResource[static_cast<int>(resourceType)] += yieldLevel;
            statusRows[static_cast<int>(resourceType)].fields[tileGreatPower] += yieldLevel;
            needCurrentByType[static_cast<int>(resourceType)] += yieldLevel;
          }
          ++edge;
        }
      }
    }
  }

  // Convert the last two status rows into aid pressure on each great power, scaled by
  // the standing-score matrix and normalized by 255.
  int powerCount;
  int power = 0;
  for (powerCount = 7; powerCount != 0; --powerCount) {
    if (g_apTerrainTypeDescriptorTable[power] != 0) {
      short pressure16 = statusRows[0x16].fields[power];
      if (pressure16 != 0) {
        g_apNationStates[power]->AddAmountToAidAllocationMatrixCellAndTotal(
            g_pDiplomacyTurnStateManager
                    ->relationStandingScoreMatrix79c[this->nationSlot * 0x17 + power] *
                pressure16 * 200 / 255,
            0x16, this->nationSlot);
      }
      short pressure15 = statusRows[0x15].fields[power];
      if (pressure15 != 0) {
        g_apNationStates[power]->AddAmountToAidAllocationMatrixCellAndTotal(
            g_pDiplomacyTurnStateManager
                    ->relationStandingScoreMatrix79c[this->nationSlot * 0x17 + power] *
                pressure15 * 500 / 255,
            0x15, this->nationSlot);
      }
    }
    ++power;
  }
}

// FUNCTION: IMPERIALISM 0x004e49b0
void TMinor::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                            int multiplier) {
  short resourceSlot = static_cast<short>(resourceIndex);
  short deltaShort = static_cast<short>(delta);

  if (deltaShort >= 1 && resourceSlot >= 0xd && resourceSlot <= 0x10) {
    if (resourceSlot == this->diplomacyPolicyPredicateCode12c) {
      this->diplomacyPolicyGate130 = deltaShort;
      return;
    }
    if (resourceSlot == this->diplomacyPolicyPredicateCode12e) {
      this->diplomacyPolicyGate132 = deltaShort;
      return;
    }
    return;
  }

  if (resourceSlot < 0 || resourceSlot > 6) {
    if (resourceSlot == 7) {
      this->diplomacyGrantByNation[7] =
          static_cast<short>(this->diplomacyGrantByNation[7] + deltaShort);
    }
    return;
  }

  this->diplomacyGrantByNation[resourceSlot] =
      static_cast<short>(this->diplomacyGrantByNation[resourceSlot] + deltaShort);
  if (this->recurringGrantByResource[resourceSlot] == 0) {
    return;
  }

  short needCurrent = this->needCurrentByType[resourceSlot];
  if (needCurrent == 0) {
    return;
  }

  for (int majorNationSlot = 0; majorNationSlot < 7; ++majorNationSlot) {
    if (g_apTerrainTypeDescriptorTable[majorNationSlot] == 0) {
      continue;
    }
    short linkValue = this->statusRows[resourceSlot].fields[majorNationSlot];
    if (linkValue == 0) {
      continue;
    }

    TGreatPower* majorNation = g_apNationStates[majorNationSlot];
    if (majorNation == 0) {
      continue;
    }

    short standing =
        g_pDiplomacyTurnStateManager
            ->relationStandingScoreMatrix79c[this->nationSlot * kNationSlotCount + majorNationSlot];
    int negDelta = -static_cast<int>(deltaShort);
    int intFactor = negDelta;
    if (negDelta < linkValue) {
      intFactor = linkValue;
    }

#if defined(_MSC_VER)
    float floatAmount = static_cast<float>(linkValue) / static_cast<float>(needCurrent);
    floatAmount = floatAmount * static_cast<float>(standing);
    floatAmount = floatAmount * static_cast<float>(multiplier);
    floatAmount = floatAmount * static_cast<float>(deltaShort);
    floatAmount = floatAmount * g_ApplyIndexedResourceDeltaScale_00653728;
    int amountFloat = static_cast<int>(floatAmount);
    int amountInt = SignedDivideBy100(intFactor * static_cast<int>(standing) * multiplier);
    int amount = amountFloat;
    if (amountInt > amount) {
      amount = amountInt;
    }
#else
    int amount = SignedDivideBy100(intFactor * static_cast<int>(standing) * multiplier);
#endif
    majorNation->AddAmountToAidAllocationMatrixCellAndTotal(amount, resourceSlot, this->nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004e4bd0
void TMinor::SeedRandomDiplomacyPolicyThresholds(void) {
  short savedPredicate = this->diplomacyPolicyPredicateCode12c;
  short proposalWeight = 0;
  if (this == 0 || this->encodedNationSlot <= 99 || this->encodedNationSlot >= 200) {
    int randomBucket = static_cast<int>(rand()) % 100;
    int resourceType = 0;
    if (randomBucket < 0x19) {
      resourceType = 0;
    } else if (randomBucket < 0x32) {
      resourceType = 1;
    } else {
      resourceType = ((0x4a < randomBucket) - 1 & 0xfffffffb) + 7;
    }

    proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(resourceType);
    if (this->diplomacyRandomThreshold124 < proposalWeight) {
      this->diplomacyPolicyByNation[resourceType] = this->needCurrentByType[resourceType];
    }

    for (int policySlot = 0; policySlot < 8; ++policySlot) {
      proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(policySlot);
      if (this->diplomacyRandomThreshold122 < proposalWeight) {
        this->diplomacyPolicyByNation[policySlot] = this->needCurrentByType[policySlot];
      }
    }

    proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(3);
    if (this->diplomacyRandomThreshold126 < proposalWeight) {
      this->diplomacyPolicyByNation[3] = this->needCurrentByType[3];
    } else if (this->recurringGrantByResource[3] != 0) {
      this->diplomacyPolicyByNation[3] = this->recurringGrantByResource[3];
    }

    proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(4);
    if (this->diplomacyRandomThreshold128 < proposalWeight) {
      this->diplomacyPolicyByNation[4] = this->needCurrentByType[4];
    } else if (this->recurringGrantByResource[4] != 0) {
      this->diplomacyPolicyByNation[4] = this->recurringGrantByResource[4];
    }

    proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(6);
    if (this->diplomacyRandomThreshold12a < proposalWeight) {
      this->diplomacyPolicyByNation[6] = this->needCurrentByType[6];
    } else if (this->recurringGrantByResource[6] != 0) {
      this->diplomacyPolicyByNation[6] = this->recurringGrantByResource[6];
    }

    if (this->diplomacyPolicyByNation[0] == 0) {
      this->diplomacyPolicyByNation[0] = this->recurringGrantByResource[0];
    }
    if (this->diplomacyPolicyByNation[1] == 0) {
      this->diplomacyPolicyByNation[1] = this->recurringGrantByResource[1];
    }
    if (this->diplomacyPolicyByNation[2] == 0) {
      this->diplomacyPolicyByNation[2] = this->recurringGrantByResource[2];
    }
  }

  if (savedPredicate == this->diplomacyPolicyPredicateCode12c) {
    short rolledPredicate = this->diplomacyPolicyPredicateCode12c;
    do {
      int roll = static_cast<int>(rand()) % 100;
      if (roll < 0x1e) {
        rolledPredicate = 0xd;
      } else if (roll < 0x3c) {
        rolledPredicate = 0xe;
      } else {
        rolledPredicate = static_cast<short>((0x59 < roll) + 0xf);
      }
    } while (rolledPredicate == this->diplomacyPolicyPredicateCode12c);
    proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(rolledPredicate);
    if (this->diplomacyRandomThreshold11e < proposalWeight) {
      this->diplomacyPolicyPredicateCode12c = -10;
    } else {
      this->diplomacyPolicyPredicateCode12c = rolledPredicate;
    }
  }

  this->diplomacyPolicyPredicateCode12e = -10;
  int candidatePredicate = 0xd;
  do {
    proposalWeight =
        g_pNationInteractionStateManager->QueryProposalWeightSlot4C(candidatePredicate);
    if (proposalWeight < this->diplomacyRandomThreshold120 &&
        candidatePredicate != this->diplomacyPolicyPredicateCode12c) {
      this->diplomacyPolicyPredicateCode12e = static_cast<short>(candidatePredicate);
      candidatePredicate = 0x11;
    }
    candidatePredicate = candidatePredicate + 1;
  } while (candidatePredicate < 0x11);

  if (this->diplomacyPolicyPredicateCode12c != -10) {
    this->diplomacyPolicyByNation[this->diplomacyPolicyPredicateCode12c] = -1;
  }
  if (this->diplomacyPolicyPredicateCode12e != -10) {
    this->diplomacyPolicyByNation[this->diplomacyPolicyPredicateCode12e] = -1;
  }
}

// FUNCTION: IMPERIALISM 0x004e4ee0
bool TMinor::IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short policyCode) {
  if (policyCode <= 0xc || policyCode >= 0x11) {
    return false;
  }
  if (policyCode == this->diplomacyPolicyPredicateCode12c) {
    return this->diplomacyPolicyGate130 == 0;
  }
  if (policyCode == this->diplomacyPolicyPredicateCode12e) {
    return this->diplomacyPolicyGate132 == 0;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004e4f50
char TMinor::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3, int arg4) {
  if (this->ReturnFalseNationStateCapabilityFlag90(arg4) == 0) {
    return 0;
  }

  g_pNationInteractionStateManager->DispatchProposalAmountSlot60(this->nationSlot, arg1, arg2, arg3,
                                                                 arg4, 1, 0);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e4fa0
void TMinor::SetTradePolicyTo(NationSlot nationSlot, short tradePolicy) {
  short targetNationSlot = static_cast<short>(nationSlot);
  short policyValue = tradePolicy;
  if (targetNationSlot != this->nationSlot) {
    if (policyValue != this->needLevelByNation[targetNationSlot]) {
      this->needLevelByNation[targetNationSlot] = policyValue;
      if (policyValue == 300) {
        this->ReassignUnitOrdersForCountryTargetChange(-1, 0);
      }
    }
  }
}

void TMinor::SetDiplomacyStandingSlot48(int targetNation, int standing) {
  this->SetTradePolicyTo(static_cast<NationSlot>(targetNation), standing);
}

char TMinor::HasMinorStandingLinkSlot5C(int sourceNation) {
  return this->IsEncodedNationSlotMinus200Equal(sourceNation);
}

void TMinor::ApplyTerrainDiplomacyRelationFlagSlot8c(int sourceNation,
                                                     DiplomacyRelationship relationship) {
  g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCode(sourceNation, this->nationSlot,
                                                                   relationship, 0);
}

char TMinor::HasStandingPropagationBridgeSlot90(int targetNation) {
  if (targetNation < 0 || targetNation >= 7) {
    return 0;
  }
  for (int resourceType = 0; resourceType < kResourceIndustrialRawCount; ++resourceType) {
    if (this->statusRows[resourceType].fields[targetNation] != 0) {
      return 1;
    }
  }
  return 0;
}

void TMinor::NotifyNationAuxRuntimeFinalizeSlotC0(void) {
  for (int resourceType = 0; resourceType < kResourceIndustrialRawCount; ++resourceType) {
    for (int majorNationSlot = 0; majorNationSlot < 7; ++majorNationSlot) {
      this->statusRows[resourceType].fields[majorNationSlot] = 0;
    }
  }
}

void TMinor::ClearNationAuxRuntimeGrantSlotC4(int grantValue) {
  if (grantValue == -1) {
    for (int resourceType = 0; resourceType < kResourceKindCount; ++resourceType) {
      this->recurringGrantByResource[resourceType] = 0;
    }
    return;
  }
  if (grantValue >= 0 && grantValue < 0x17) {
    this->recurringGrantByResource[grantValue] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004e4ff0
char TMinor::CanInitiateJoinEmpireProposalToTarget(NationSlot targetNationSlot,
                                                   DiplomacyProposalCodeStorage proposalCode) {
  if (proposalCode != kDiplomacyProposalJoinEmpire || this->encodedNationSlot != -1) {
    return 0;
  }

  const int source = this->nationSlot;
  short standing =
      g_pDiplomacyTurnStateManager
          ->relationStandingScoreMatrix79c[source * kNationSlotCount + targetNationSlot];
  if (standing <= 0xf9) {
    return 0;
  }

  char canPropose = 1;
  short* peerStandingRow =
      &g_pDiplomacyTurnStateManager->relationStandingScoreMatrix79c[source * kNationSlotCount];
  for (int peerSlot = 0; peerSlot < 7; ++peerSlot) {
    if (peerSlot == targetNationSlot || g_apTerrainTypeDescriptorTable[peerSlot] == 0) {
      continue;
    }
    int delta = static_cast<int>(peerStandingRow[peerSlot]) - static_cast<int>(standing);
    if (delta < 0) {
      delta = -delta;
    }
    if (delta < 10) {
      canPropose = 0;
      break;
    }
  }
  return canPropose;
}

// FUNCTION: IMPERIALISM 0x004e50d0
void TMinor::QueueDiplomacyProposalCodeForTargetNation(DiplomacyProposalCodeStorage proposalCode,
                                                       NationSlot targetNationSlot) {
  NationSlot targetNation = targetNationSlot;
  if (proposalCode == kDiplomacyProposalJoinEmpire) {
    char canPropose = 0;
    if (this->encodedNationSlot == -1) {
      canPropose = this->CanInitiateJoinEmpireProposalToTarget(targetNation, proposalCode);
    }
    if (canPropose != 0) {
      if (g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(this->nationSlot,
                                                                      targetNation) == 0) {
        this->SetTradePolicyTo(static_cast<NationSlot>(targetNation), 1);
        g_pNewsMgr->AddTreatyEvent(kInterNationEventJoinEmpireAccepted, this->nationSlot,
                                   targetNation, 0);
        return;
      }
      if (g_apNationStates[targetNation] != 0) {
        g_apNationStates[targetNation]->QueueDiplomacyProposalCodeForTargetNation(
            kDiplomacyProposalJoinEmpireWithWarEntanglements, this->nationSlot);
      }
      g_pNewsMgr->AddTreatyEvent(kInterNationEventJoinEmpireAccepted, this->nationSlot,
                                 targetNation, 0);
      return;
    }
    if (g_apNationStates[targetNation] != 0) {
      g_apNationStates[targetNation]->NotifyActionSlot94(this->nationSlot,
                                                         -static_cast<int>(proposalCode));
    }
    g_pNewsMgr->AddTreatyEvent(kInterNationEventJoinEmpireRejected, targetNation, this->nationSlot,
                               0);
    return;
  }

  if (proposalCode == kDiplomacyProposalNonAggressionPact) {
    if (this->encodedNationSlot == -1) {
      g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
          this->nationSlot, targetNation, kDiplomacyRelationshipNonAggressionPact);
      if (g_apNationStates[targetNation] != 0) {
        g_apNationStates[targetNation]->NotifyActionSlot94(this->nationSlot, proposalCode);
      }
      g_pNewsMgr->AddTreatyEvent(kInterNationEventNonAggressionPactAccepted, this->nationSlot,
                                 targetNation, 0);
    }
    return;
  }

  if (proposalCode == kDiplomacyProposalPeaceTreaty && this->encodedNationSlot == -1) {
    g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
        this->nationSlot, targetNation, kDiplomacyRelationshipPeace);
    if (g_apNationStates[targetNation] != 0) {
      g_apNationStates[targetNation]->NotifyActionSlot94(this->nationSlot, proposalCode);
    }
    g_pNewsMgr->AddTreatyEvent(kInterNationEventPeaceTreatyAccepted, this->nationSlot, targetNation,
                               0);
  }
}

// FUNCTION: IMPERIALISM 0x004e5300
void TMinor::NotifyActionSlot94(int sourceNation, int actionCode) {
  (void)sourceNation;
  if (actionCode == kDiplomacyProposalDeclareWar) {
    this->ApplyDiplomacyRelationMaskToProvinceLinkedObjects(-1);
    this->NotifyMajorPowersAffectedByMinorTerritoryChange();
  }
}

// FUNCTION: IMPERIALISM 0x004e5340
void TMinor::SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot) {
  this->SetNationRowDisplayValueByDiplomacyPredicate(static_cast<NationSlot>(targetNationSlot));

  if (this->encodedNationSlot < 200) {
    this->encodedNationSlot = static_cast<short>(targetNationSlot + 100);

    for (int eligibleNationSlot = 0; eligibleNationSlot < kNationSlotCount; ++eligibleNationSlot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(
              static_cast<short>(eligibleNationSlot)) != 0 &&
          eligibleNationSlot != this->nationSlot && eligibleNationSlot != targetNationSlot) {
        TCountry* terrain = g_apTerrainTypeDescriptorTable[eligibleNationSlot];
        if (terrain != 0) {
          terrain->SetNationPercentFieldByModeAndDescriptorLinks(this->nationSlot, 100);
        }
      }
    }
    g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);

    for (int majorNationSlot = 0; majorNationSlot < 7; ++majorNationSlot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(majorNationSlot)) !=
          0) {
        TGreatPower* majorNation = g_apNationStates[majorNationSlot];
        if (majorNation != 0 && majorNation->diplomacyEligibilityA0 == 0) {
          majorNation->NotifyActionSlot94(this->nationSlot, kDiplomacyProposalDeclareWar);
        }
        g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCode(
            this->nationSlot, majorNationSlot, kDiplomacyRelationshipWar, 0);
        g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, majorNationSlot,
                                                             0x31);
      }
    }

    for (int minorSlot = 7; minorSlot < kNationSlotCount; ++minorSlot) {
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, minorSlot, 0x6e);
    }
    return;
  }

  short decodedNationSlot =
      DecodeTerrainNationSlotFromEncoded(this->encodedNationSlot, this->nationSlot);

  TGreatPower* targetMajor = g_apNationStates[decodedNationSlot];
  if (targetMajor != 0) {
    targetMajor->NotifyActionSlot94(this->nationSlot, 0x13c);
  }
  g_pNewsMgr->AddTreatyEvent(kInterNationEventMinorEmpireAffiliationChanged, decodedNationSlot,
                             this->nationSlot, 0);

  for (int resetNationSlot = 0; resetNationSlot < kNationSlotCount; ++resetNationSlot) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(resetNationSlot)) !=
        0) {
      g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
          this->nationSlot, resetNationSlot, kDiplomacyRelationshipPeace);
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, resetNationSlot, 0x5a);
    }
  }

  short ownedRegionIds[10];
  for (int index = 0; index < 10; ++index) {
    ownedRegionIds[index] = -1;
  }

  if (this->ownedRegionList != 0) {
    int ownedCount = this->ownedRegionList->GetSize();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      short regionId = static_cast<short>(this->ownedRegionList->At(oneBasedIndex));
      if (oneBasedIndex - 1 < 10) {
        ownedRegionIds[oneBasedIndex - 1] = regionId;
      }
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetSize();
    }
  }

  if (g_pMapContextActionManager != 0) {
    for (int index = 0; index < 10; ++index) {
      int regionId = ownedRegionIds[index];
      if (regionId == -1) {
        continue;
      }
      short regionOwner = g_pMapContextActionManager->perTileOwnerNationCodeCache1c[regionId];
      if (regionOwner == this->nationSlot || regionOwner == decodedNationSlot) {
        g_pGlobalMapState->DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(
            static_cast<short>(regionId), decodedNationSlot);
      }
    }
  }

  this->encodedNationSlot = static_cast<short>(targetNationSlot + 100);
  for (int linkNationSlot = 0; linkNationSlot < kNationSlotCount; ++linkNationSlot) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(linkNationSlot)) !=
            0 &&
        linkNationSlot != this->nationSlot && linkNationSlot != targetNationSlot) {
      TCountry* terrain = g_apTerrainTypeDescriptorTable[linkNationSlot];
      if (terrain != 0) {
        terrain->SetNationPercentFieldByModeAndDescriptorLinks(this->nationSlot, 100);
      }
    }
  }
  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);

  for (int standingNationSlot = 0; standingNationSlot < 7; ++standingNationSlot) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(standingNationSlot)) !=
        0) {
      if (standingNationSlot == targetNationSlot) {
        this->SetDiplomacyStandingSlot48(standingNationSlot, 100);
        if (g_apNationStates[standingNationSlot] != 0) {
          g_apNationStates[standingNationSlot]->SetTradePolicyTo(this->nationSlot, 100);
          g_apNationStates[standingNationSlot]->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(
              this->nationSlot, static_cast<unsigned short>(-1));
        }
      } else {
        this->SetDiplomacyStandingSlot48(standingNationSlot, 300);
        if (g_apNationStates[standingNationSlot] != 0) {
          g_apNationStates[standingNationSlot]->SetTradePolicyTo(this->nationSlot, 300);
        }
      }
    }
  }

  this->NotifyMajorPowersAffectedByMinorTerritoryChange();
  if (g_apNationStates[targetNationSlot] != 0 &&
      g_apNationStates[targetNationSlot]->serializedStatusFlags[6] < '3') {
    g_apNationStates[targetNationSlot]->SetNationPendingActionStateAndPayload(6, this->nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004e5730
void TMinor::HandleNetworkPortConstructionOrder(int nationId) {
  unsigned char nationTileFlags = static_cast<unsigned char>(
      g_pGlobalMapState->terrainStateTable[static_cast<short>(this->homeTileIndex)].activeFlags1c);
  if ((nationTileFlags >> 2 & 1) != 0) {
    return;
  }

  TTown* marker = new TTown();
  marker->ITown("", this->homeTileIndex, 1, static_cast<short>(nationId));
  marker->activeFlag4f = 1;
  g_pGlobalMapState->SetTileTransportFlags(static_cast<short>(this->homeTileIndex), 0x15);
  TGreatPower* targetNation = g_apNationStates[nationId];
  if (targetNation != 0 && targetNation->townMarkerList != 0) {
    targetNation->townMarkerList->AddTail(marker);
  }
}

// FUNCTION: IMPERIALISM 0x004e5840
void TMinor::ApplyJoinEmpireMode1TargetTransition(int targetNationSlot) {
  TCountry::ApplyJoinEmpireMode1TargetTransition(targetNationSlot);
  g_pNewsMgr->AddTreatyEvent(kInterNationEventNationJoinedEmpire, this->nationSlot,
                             targetNationSlot, 0);
}

// FUNCTION: IMPERIALISM 0x004e59d0
void TMinor::ApplyJoinEmpireMode2FinalizeNationNameState(void) {
  short decodedSlot = DecodeTerrainNationSlotFromEncoded(this->encodedNationSlot, this->nationSlot);
  this->encodedNationSlot = -1;
  this->SetNationRowDisplayValueByDiplomacyPredicate(decodedSlot);
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    this->SetDiplomacyStandingSlot48(nationSlot, 100);
  }
}

// FUNCTION: IMPERIALISM 0x004e5a40
void TMinor::SetNationRowDisplayValueByDiplomacyPredicate(NationSlot targetNationSlot) {
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(targetNationSlot, nationSlot) == 0 &&
        (nationSlot == this->nationSlot ||
         (g_apNationStates[targetNationSlot] != 0 &&
          reinterpret_cast<unsigned char*>(
              g_apNationStates[targetNationSlot])[0x918 + nationSlot] == 0))) {
      this->SetTradePolicyTo(static_cast<NationSlot>(nationSlot), 100);
    } else {
      this->SetTradePolicyTo(static_cast<NationSlot>(nationSlot), 300);
    }
  }
}

namespace {

void DispatchCivilianOrderRelationMaskSlots(TUnit* orderNode) {
  if (orderNode->orderType == EncodeCivilianUnitKind(kCivilianUnitDeveloper)) {
    TGreatPower* ownerNation = g_apNationStates[orderNode->field_18];
    if (ownerNation != 0) {
      short payload = static_cast<short>(ownerNation->homeTileIndex);
      orderNode->MoveTo(static_cast<int>(payload));
    }
    return;
  }
  orderNode->DetachUnitOrderFromOwnerAndReset();
  orderNode->MoveTo(-1);
}

void WalkTileCivilianOrdersForRelationMask(TTerrainStateRecordView* terrainTiles, short tileId,
                                           const char* relationMaskByNation) {
  TUnit* orderNode = terrainTiles[tileId].firstCivilianOrder20;
  while (orderNode != 0) {
    TUnit* nextNode = orderNode->nextOnTile;
    if (relationMaskByNation[orderNode->field_18] != 0) {
      DispatchCivilianOrderRelationMaskSlots(orderNode);
    }
    orderNode = nextNode;
  }
}

int ResolveDiplomacyMaskOwnerNationSlot(const TMinor* minor, short provinceId) {
  if (provinceId != -1) {
    return g_pGlobalMapState->cityScoreTable[provinceId].ownerNationCode00;
  }
  return DecodeTerrainNationSlotFromEncoded(minor->encodedNationSlot, minor->nationSlot);
}

} // namespace

// FUNCTION: IMPERIALISM 0x004e5ac0
void TMinor::ClearTileActivityOverlayByProvinceId(int provinceId) {
  char* tileArrayBase = reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable);
  if (provinceId == -1) {
    if (this->ownedRegionList == 0) {
      return;
    }
    int ownedCount = this->ownedRegionList->GetSize();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      int regionId = this->ownedRegionList->At(oneBasedIndex);
      Province* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
      if (regionRecord->linkedRegionCount > 0) {
        int linkedIndex = 0;
        while (linkedIndex < regionRecord->linkedRegionCount) {
          short tileId = regionRecord->linkedTileIndices42[linkedIndex];
          tileArrayBase[0x18 + tileId * 0x24] = static_cast<char>(-1);
          linkedIndex++;
        }
      }
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetSize();
    }
    return;
  }

  Province* regionRecord = &g_pGlobalMapState->cityScoreTable[provinceId];
  if (regionRecord->linkedRegionCount > 0) {
    int linkedIndex = 0;
    while (linkedIndex < regionRecord->linkedRegionCount) {
      short tileId = regionRecord->linkedTileIndices42[linkedIndex];
      tileArrayBase[0x18 + tileId * 0x24] = static_cast<char>(-1);
      linkedIndex++;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e5be0
void TMinor::NotifyMajorPowersAffectedByMinorTerritoryChange(void) {
  int majorSlot;
  char needLevel300ByMajorSlot[7];
  for (majorSlot = 0; majorSlot < 7; ++majorSlot) {
    needLevel300ByMajorSlot[majorSlot] = (this->needLevelByNation[majorSlot + 1] == 300) ? 1 : 0;
  }

  char notifyMajorSlots[7] = {0};
  TTerrainStateRecordView* terrainTiles = g_pGlobalMapState->terrainStateTable;
  char* terrainBytes = reinterpret_cast<char*>(terrainTiles);

  if (this->ownedRegionList != 0) {
    int ownedCount = this->ownedRegionList->GetSize();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      int regionId = this->ownedRegionList->At(oneBasedIndex);
      Province* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
      if (regionRecord->linkedRegionCount > 0) {
        int linkedIndex = 0;
        while (linkedIndex < regionRecord->linkedRegionCount) {
          short tileId = regionRecord->linkedTileIndices42[linkedIndex];
          int tileNation = static_cast<signed char>(terrainBytes[0x18 + tileId * 0x24]);
          if (tileNation != -1 && needLevel300ByMajorSlot[tileNation] != 0) {
            notifyMajorSlots[tileNation] = 1;
            terrainBytes[0x18 + tileId * 0x24] = static_cast<char>(-1);
          }
          linkedIndex++;
        }
      }
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetSize();
    }
  }

  for (majorSlot = 0; majorSlot < 7; ++majorSlot) {
    if (g_apNationStates[majorSlot] != 0 && notifyMajorSlots[majorSlot] != 0) {
      g_apNationStates[majorSlot]->NotifyActionSlot94(this->nationSlot, 0x137);
      g_pNewsMgr->AddTreatyEvent(kInterNationEventMinorTerritoryRelationshipAffected, majorSlot,
                                 this->nationSlot, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e5d90
void TMinor::ApplyDiplomacyRelationMaskToProvinceLinkedObjects(short provinceId) {
  const int ownerNationSlot = ResolveDiplomacyMaskOwnerNationSlot(this, provinceId);

  char relationMaskByNation[kTerrainTypeDescriptorTableCount];
  for (int nationSlot = 0; nationSlot < kTerrainTypeDescriptorTableCount; ++nationSlot) {
    relationMaskByNation[nationSlot] = 0;
    if (g_apTerrainTypeDescriptorTable[nationSlot] != 0 && nationSlot != ownerNationSlot &&
        g_pDiplomacyTurnStateManager->IsNationPairAtWar(ownerNationSlot, nationSlot) != 0) {
      relationMaskByNation[nationSlot] = 1;
    }
  }

  TTerrainStateRecordView* terrainTiles = g_pGlobalMapState->terrainStateTable;
  if (provinceId == -1) {
    if (this->ownedRegionList == 0) {
      return;
    }
    int ownedCount = this->ownedRegionList->GetSize();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      int regionId = this->ownedRegionList->At(oneBasedIndex);
      Province* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
      if (regionRecord->linkedRegionCount > 0) {
        int linkedIndex = 0;
        while (linkedIndex < regionRecord->linkedRegionCount) {
          WalkTileCivilianOrdersForRelationMask(
              terrainTiles, regionRecord->linkedTileIndices42[linkedIndex], relationMaskByNation);
          linkedIndex++;
        }
      }
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetSize();
    }
    return;
  }

  Province* regionRecord = &g_pGlobalMapState->cityScoreTable[provinceId];
  if (regionRecord->linkedRegionCount > 0) {
    int linkedIndex = 0;
    while (linkedIndex < regionRecord->linkedRegionCount) {
      WalkTileCivilianOrdersForRelationMask(
          terrainTiles, regionRecord->linkedTileIndices42[linkedIndex], relationMaskByNation);
      linkedIndex++;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e6040
void TMinor::ReassignTileObjectOwnerAndNotifyForSelectedCells(int priorOwnerNationSlot) {
  TSortedList* destinationManager =
      g_apTerrainTypeDescriptorTable[priorOwnerNationSlot]->militaryUnitList44;
  if (this->ownedRegionList == 0 || destinationManager == 0 || this->militaryUnitList44 == 0) {
    return;
  }

  int ownedCount = this->ownedRegionList->GetSize();
  int oneBasedIndex = 1;
  while (oneBasedIndex <= ownedCount) {
    short regionId = static_cast<short>(this->ownedRegionList->At(oneBasedIndex));
    if (regionId < 0 || regionId >= 0x180) {
      oneBasedIndex++;
      continue;
    }
    TMilitaryUnit* unitNode = g_pGlobalMapState->cityScoreTable[regionId].stationedUnitChain98;
    while (unitNode != 0) {
      TUnit* unit = unitNode;
      TMilitaryUnit* nextNode = static_cast<TMilitaryUnit*>(unitNode->nextOnTile);
      if (unit->field_18 == priorOwnerNationSlot) {
        unit->field_18 = this->nationSlot;
        CPtrList* sourceList = &this->militaryUnitList44->listState;
        POSITION pos = sourceList->Find(unit, 0);
        if (pos != 0) {
          sourceList->RemoveAt(pos);
        }
        destinationManager->AddTail(unit);
      }
      unitNode = nextNode;
    }
    oneBasedIndex++;
    ownedCount = this->ownedRegionList->GetSize();
  }
}

namespace {

void RetargetUnitOrderForAllowedNation(TUnit* orderNode) {
  short ownerNationSlot = orderNode->field_18;
  TGreatPower* ownerNation = g_apNationStates[ownerNationSlot];
  if (ownerNation == 0) {
    return;
  }
  short homeTileIndex = static_cast<short>(ownerNation->homeTileIndex);
  short spawnTile =
      g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(homeTileIndex, 0);
  if (spawnTile == -1) {
    orderNode->DetachUnitOrderFromOwnerAndReset();
    orderNode->Free();
    return;
  }
  orderNode->MoveTo(static_cast<int>(spawnTile));
}

void RetargetUnitOrderForAllowedNationWithModeReset(TUnit* orderNode) {
  short ownerNationSlot = orderNode->field_18;
  TGreatPower* ownerNation = g_apNationStates[ownerNationSlot];
  if (ownerNation == 0) {
    return;
  }
  short homeTileIndex = static_cast<short>(ownerNation->homeTileIndex);
  short spawnTile =
      g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(homeTileIndex, 0);
  if (spawnTile == -1) {
    orderNode->DetachUnitOrderFromOwnerAndReset();
    orderNode->Free();
    return;
  }
  orderNode->SetOrders(kUnitOrderIdle, -1);
  orderNode->MoveTo(static_cast<int>(spawnTile));
}

void WalkTileUnitOrdersForRelationMask(TTerrainStateRecordView* terrainTiles, short tileId,
                                       const char* relationMaskByNation, char resetOrderMode) {
  TUnit* orderNode = terrainTiles[tileId].firstCivilianOrder20;
  while (orderNode != 0) {
    TUnit* nextNode = orderNode->nextOnTile;
    if (relationMaskByNation[orderNode->field_18] != 0) {
      if (resetOrderMode != 0) {
        RetargetUnitOrderForAllowedNationWithModeReset(orderNode);
      } else {
        RetargetUnitOrderForAllowedNation(orderNode);
      }
    }
    orderNode = nextNode;
  }
}

} // namespace

// FUNCTION: IMPERIALISM 0x004e6150
void TMinor::ReassignUnitOrdersForCountryTargetChange(short provinceId,
                                                      char includeAllPolicyTargets) {
  if (includeAllPolicyTargets == 0) {
    this->NotifyMajorPowersAffectedByMinorTerritoryChange();
  }

  int ownerNationSlot;
  if (provinceId == -1) {
    ownerNationSlot = DecodeTerrainNationSlotFromEncoded(this->encodedNationSlot, this->nationSlot);
  } else {
    ownerNationSlot = g_pGlobalMapState->cityScoreTable[provinceId].ownerNationCode00;
  }

  char relationMaskByNation[kTerrainTypeDescriptorTableCount];
  for (int nationSlot = 0; nationSlot < kTerrainTypeDescriptorTableCount; ++nationSlot) {
    relationMaskByNation[nationSlot] = 0;
    if (g_apTerrainTypeDescriptorTable[nationSlot] != 0 && nationSlot != ownerNationSlot &&
        (includeAllPolicyTargets != 0 ||
         g_pDiplomacyTurnStateManager->IsNationPairAtWar(this->nationSlot, nationSlot) != 0)) {
      relationMaskByNation[nationSlot] = 1;
    }
  }

  TTerrainStateRecordView* terrainTiles = g_pGlobalMapState->terrainStateTable;
  if (provinceId == -1) {
    if (this->ownedRegionList == 0) {
      return;
    }
    int ownedCount = this->ownedRegionList->GetSize();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      int regionId = this->ownedRegionList->At(oneBasedIndex);
      Province* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
      if (regionRecord->linkedRegionCount > 0) {
        int linkedIndex = 0;
        while (linkedIndex < regionRecord->linkedRegionCount) {
          WalkTileUnitOrdersForRelationMask(terrainTiles,
                                            regionRecord->linkedTileIndices42[linkedIndex],
                                            relationMaskByNation, 0);
          linkedIndex++;
        }
      }
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetSize();
    }
    return;
  }

  Province* regionRecord = &g_pGlobalMapState->cityScoreTable[provinceId];
  if (regionRecord->linkedRegionCount > 0) {
    int linkedIndex = 0;
    while (linkedIndex < regionRecord->linkedRegionCount) {
      WalkTileUnitOrdersForRelationMask(
          terrainTiles, regionRecord->linkedTileIndices42[linkedIndex], relationMaskByNation, 1);
      linkedIndex++;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e64a0
void TMinor::RemoveRegionIdFromNationOwnedRegionList(int regionId) {
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->Delete(regionId);
  }
  this->ClearTileActivityOverlayByProvinceId(regionId);
  this->ApplyDiplomacyRelationMaskToProvinceLinkedObjects(regionId);
  this->ReassignUnitOrdersForCountryTargetChange(static_cast<short>(regionId), 1);
}

// FUNCTION: IMPERIALISM 0x004e64f0
void TMinor::AddRegionIdToNationOwnedRegionList(int regionId) {
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->InsertLast(regionId);
  }
}

// FUNCTION: IMPERIALISM 0x004e6520
void TMinor::RelinkTileUnitsToCountryOrderManager(int destinationNationSlot) {
  TSortedList* destinationManager =
      g_apTerrainTypeDescriptorTable[destinationNationSlot]->militaryUnitList44;
  if (destinationManager == 0 || this->militaryUnitList44 == 0) {
    return;
  }

  CIterator unitCursor(this->militaryUnitList44);
  TUnit* unit = static_cast<TUnit*>(unitCursor.Reset());
  while (unitCursor.More() != 0) {
    unit->field_18 = static_cast<short>(destinationNationSlot);
    CPtrList* sourceList = &this->militaryUnitList44->listState;
    POSITION pos = sourceList->Find(unit, 0);
    if (pos != 0) {
      sourceList->RemoveAt(pos);
    }
    destinationManager->AddTail(unit);
    unit = static_cast<TUnit*>(unitCursor.Advance());
  }
}
