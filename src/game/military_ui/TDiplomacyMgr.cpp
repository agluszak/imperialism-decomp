#include "game/diplomacy_domain_types.h"
#include "game/ui_tags_military.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/military/NetMessage.h"
#include "game/net/TMultiplayerMgr.h"
#include <string.h>
#include "game/map/TIndexAndRankList.h"
#include "game/map/TMapMgr.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/ui_screens/CString.h"
#include "game/nation/TGreatPower.h"
#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
#include "game/city_ui/TLongintList.h"
#include "game/nation/TMinor.h"
#include "game/ui_widgets/TNextTradeCommand.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_core/TApplication.h"
#include "game/core/TStream.h"
#include <new>
#include <stdlib.h>

namespace {
const unsigned int kTurnEventTagNext = kControlTagNeXT;
struct ScratchSharedString {
  CString str;
  ScratchSharedString() {}
};
} // namespace

static __inline void InitializeRangePairAndResetCursor(TNextTradeCommand* packet, int eventTag,
                                                       TApplication* owner) {
  packet->InitializeRangePair(eventTag, owner, 0, 0, 0);
}

static __inline TDiplomacyMgr* ReadGlobalTDiplomacyTurnStateManager() {
  return g_pDiplomacyTurnStateManager;
}

struct WarTransitionPair {
  short sourceNationSlot;
  short targetNationSlot;
};

namespace {

short DecodeTerrainDescriptorNationSlotForAdjacency(int terrainRecord) {
  short encodedSlot = *reinterpret_cast<short*>(terrainRecord + 0xe);
  if (encodedSlot < 200) {
    if (encodedSlot < 100) {
      return *reinterpret_cast<short*>(terrainRecord + 0xc);
    }
    return encodedSlot - 100;
  }
  return encodedSlot - 200;
}

} // namespace

// FUNCTION: IMPERIALISM 0x00413250
int TDiplomacyMgr::SelectBestMajorNationForMinorByStandingAndNeed(int minorNationSlot) {
  int bestScore = 0;
  int selectedNation = -1;
  for (int majorNation = 0; majorNation < 7; ++majorNation) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(majorNation)) == 0) {
      continue;
    }

    int score = (200 - g_apNationStates[majorNation]->needLevelByNation[minorNationSlot]) *
                relationStandingScoreMatrix79c[minorNationSlot * kNationSlotCount + majorNation];
    bool select = score > bestScore;
    if (score == bestScore) {
      select = g_apTerrainTypeDescriptorTable[minorNationSlot]->IsEncodedNationSlotMinus200Equal(
                   majorNation) != 0;
      if (!select) {
        unsigned int tieSeed =
            minorNationSlot * 7 + majorNation + g_pSimMgr->GetEconomicTurn() + score;
        if (tieSeed == 0) {
          tieSeed = minorNationSlot;
        }
        tieSeed = tieSeed * 0x15a4e35 + 1;
        select = ((tieSeed >> 12) & 1) != 0;
      }
    }
    if (select) {
      bestScore = score;
      selectedNation = majorNation;
    }
  }
  return selectedNation;
}
// SYNTHETIC: IMPERIALISM 0x004ee650
// TDiplomacyMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ee6a0
// TDiplomacyMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDiplomacyMgr, TObject)

// FUNCTION: IMPERIALISM 0x004ee6c0
TDiplomacyMgr::TDiplomacyMgr()
    : relationMatrixBaselineCopy794(0), relationMatrixBaselineSize798(0) {
  proposalDispatchCounter790 = 0;
  lastProcessedNationSlot78e = -1;
}

// SYNTHETIC: IMPERIALISM 0x004ee700
// TDiplomacyMgr::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004ee730
TDiplomacyMgr::~TDiplomacyMgr() {}

// FUNCTION: IMPERIALISM 0x004ee7a0
void TDiplomacyMgr::InitializeTDiplomacyTurnStateManagerDefaults() {
  TSortedPtrList* queue = new TSortedPtrList();
  queue->recordSize14 = 4;
  pendingWarTransitionQueue18d4 = queue;

  register int zero = 0;

  short* relationCode = relationCodeMatrix04;
  signed char* pendingPolicyCode = pendingPolicyCodeMatrix304;
  int pairCount = kDiplomacyPairMatrixEntries;

  do {
    *relationCode = static_cast<short>(zero);
    *pendingPolicyCode = -1;
    ++relationCode;
    ++pendingPolicyCode;
    --pairCount;
  } while (pairCount != 0);

  selectedSourceNationSlot784 = static_cast<short>(-1);
  selectedTargetNationSlot786 = static_cast<short>(-1);
  selectionFlagsA788 = static_cast<short>(zero);
  selectionFlagsB78a = static_cast<short>(zero);
  selectionFlagsC78c = static_cast<short>(zero);
  proposalArrayMode18d8 = static_cast<short>(zero);

  short* rowStart = relationTurnStampMatrixFe0;
  int rowCount = kNationSlotCount;

  do {
    short* linearTurnStamp = rowStart;
    short* transposeTurnStamp = rowStart;
    int columnCount = kNationSlotCount;

    do {
      *linearTurnStamp = static_cast<short>(-1);
      *transposeTurnStamp = static_cast<short>(-1);

      ++linearTurnStamp;
      transposeTurnStamp += kNationSlotCount;

      --columnCount;
    } while (columnCount != 0);

    ++rowStart;
    --rowCount;
  } while (rowCount != 0);
}

// FUNCTION: IMPERIALISM 0x004ee8c0
void TDiplomacyMgr::RebuildCivilianOrderCompatibilityMatrices() {
  int sourceNation;
  int targetNation;

  for (sourceNation = 0; sourceNation < kNationSlotCount; ++sourceNation) {
    for (targetNation = 0; targetNation < kNationSlotCount; ++targetNation) {
      int forwardIndex = sourceNation * kNationSlotCount + targetNation;
      int reverseIndex = targetNation * kNationSlotCount + sourceNation;
      relationSideEffectMatrix1402[forwardIndex] = 0;
      relationSideEffectMatrix1402[reverseIndex] = 0;

      short standingScore = 0x5a;
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(sourceNation)) !=
              0 &&
          g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(targetNation)) !=
              0) {
        if (sourceNation < 7 && g_apNationStates[sourceNation]->diplomacyEligibilityA0 == 0 &&
            g_pSimMgr->difficultyLevel > 2) {
          standingScore = static_cast<short>(g_pSimMgr->difficultyLevel == 4 ? 0x69 : 0x64);
        }
      }
      relationStandingScoreMatrix79c[forwardIndex] = standingScore;
      relationPropagationMatrixBbe[forwardIndex] = kDiplomacyRelationshipPeace;
    }
  }

  for (sourceNation = 7; sourceNation < kNationSlotCount; ++sourceNation) {
    TMinor* sourceMinor = g_apMinorNationCapabilityObjects[sourceNation - 7];
    for (targetNation = 7; targetNation < kNationSlotCount; ++targetNation) {
      int pairIndex = sourceNation * kNationSlotCount + targetNation;
      short standingScore = 0x5a;
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(sourceNation)) !=
              0 &&
          g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(targetNation)) !=
              0) {
        standingScore =
            sourceMinor->HasStandingPropagationBridgeSlot90(targetNation) != 0 ? 0x96 : 0x6e;
      }
      relationStandingScoreMatrix79c[pairIndex] = standingScore;
      relationPropagationMatrixBbe[pairIndex] = kDiplomacyRelationshipPeace;
    }
  }

  for (sourceNation = 0; sourceNation < kNationSlotCount; ++sourceNation) {
    relationStandingScoreMatrix79c[sourceNation * (kNationSlotCount + 1)] = 0xff;
  }

  for (sourceNation = 0; sourceNation < 7; ++sourceNation) {
    for (targetNation = 0; targetNation < 7; ++targetNation) {
      int forwardIndex = sourceNation * kNationSlotCount + targetNation;
      int reverseIndex = targetNation * kNationSlotCount + sourceNation;
      if (sourceNation == targetNation) {
        relationSideEffectMatrix1402[forwardIndex] = 0;
      } else {
        relationSideEffectMatrix1402[forwardIndex] = 2;
        relationSideEffectMatrix1402[reverseIndex] = 2;
      }
    }
  }

  for (sourceNation = 0; sourceNation < 0x10; ++sourceNation) {
    specialRelationSourceSlots1894[sourceNation] = -1;
    specialRelationTargetSlots18b4[sourceNation] = -1;
  }

  if (g_pSimMgr->difficultyLevel == 0) {
    for (sourceNation = 0; sourceNation < 7; ++sourceNation) {
      TGreatPower* sourcePower = g_apNationStates[sourceNation];
      if (sourcePower != 0 && sourcePower->diplomacyEligibilityA0 != 0) {
        int firstMinorNation = (abs(rand()) % 4) * 4 + 7;
        int lastMinorNation = firstMinorNation + 4;
        for (targetNation = firstMinorNation; targetNation < lastMinorNation; ++targetNation) {
          int forwardIndex = sourceNation * kNationSlotCount + targetNation;
          int reverseIndex = targetNation * kNationSlotCount + sourceNation;
          relationSideEffectMatrix1402[forwardIndex] = 1;
          relationSideEffectMatrix1402[reverseIndex] = 1;
          g_pNewsMgr->AddTreatyEvent(kInterNationEventTradeConsulateEstablished, sourceNation,
                                     targetNation, 0);
          relationStandingScoreMatrix79c[forwardIndex] = 0x6e;
          relationStandingScoreMatrix79c[reverseIndex] = 0x6e;
        }
      }
    }
  }

  if (g_pSimMgr->difficultyLevel > 2) {
    for (sourceNation = 0; sourceNation < 7; ++sourceNation) {
      if (g_apNationStates[sourceNation]->diplomacyEligibilityA0 == 0) {
        targetNation = abs(rand()) % 0x10 + 7;
        int forwardIndex = sourceNation * kNationSlotCount + targetNation;
        int reverseIndex = targetNation * kNationSlotCount + sourceNation;
        relationSideEffectMatrix1402[forwardIndex] = 1;
        relationSideEffectMatrix1402[reverseIndex] = 1;
        g_pNewsMgr->AddTreatyEvent(kInterNationEventTradeConsulateEstablished, sourceNation,
                                   targetNation, 0);
        relationStandingScoreMatrix79c[forwardIndex] = 0x6e;
        relationStandingScoreMatrix79c[reverseIndex] = 0x6e;
      }
    }
  }

  if (g_pSimMgr->difficultyLevel == 4) {
    for (sourceNation = 0; sourceNation < 7; ++sourceNation) {
      if (g_apNationStates[sourceNation]->diplomacyEligibilityA0 == 0) {
        for (targetNation = 0; targetNation < 7; ++targetNation) {
          if (g_apNationStates[targetNation]->diplomacyEligibilityA0 == 0) {
            relationStandingScoreMatrix79c[sourceNation * kNationSlotCount + targetNation] = 0x6e;
            relationStandingScoreMatrix79c[targetNation * kNationSlotCount + sourceNation] = 0x6e;
          }
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004eee60
void TDiplomacyMgr::RemoveNationSlotAndNotifyPeers_Impl(NationSlot nationSlot) {
  const int row = nationSlot;
  // Great-power slots 0..6: clear the propagation-matrix entry (both [row][i] and [i][row])
  // unless it already holds the "6" sentinel and the nation still has a terrain descriptor.
  // When the descriptor is gone, also reset the standing score to 0x5a in both directions.
  for (int i = 0; i < 7; ++i) {
    if (relationPropagationMatrixBbe[row * kNationSlotCount + i] != kDiplomacyRelationshipWar ||
        g_apTerrainTypeDescriptorTable[row] == 0) {
      relationPropagationMatrixBbe[row * kNationSlotCount + i] = kDiplomacyRelationshipPeace;
      relationPropagationMatrixBbe[i * kNationSlotCount + row] = kDiplomacyRelationshipPeace;
      if (g_apTerrainTypeDescriptorTable[row] == 0) {
        relationStandingScoreMatrix79c[row * kNationSlotCount + i] = 0x5a;
        relationStandingScoreMatrix79c[i * kNationSlotCount + row] = 0x5a;
      }
    }
  }
  // Minor slots 7..22: unconditionally reset both matrices in both directions.
  for (int j = 7; j < kNationSlotCount; ++j) {
    relationPropagationMatrixBbe[row * kNationSlotCount + j] = kDiplomacyRelationshipPeace;
    relationPropagationMatrixBbe[j * kNationSlotCount + row] = kDiplomacyRelationshipPeace;
    relationStandingScoreMatrix79c[row * kNationSlotCount + j] = 0x5a;
    relationStandingScoreMatrix79c[j * kNationSlotCount + row] = 0x5a;
  }
}

// FUNCTION: IMPERIALISM 0x004eef50
void TDiplomacyMgr::ResetTerrainAdjacencyMatrixRowAndSymmetricLink(NationSlot nationSlot) {
  int row = nationSlot;
  int remaining = kNationSlotCount;
  short* rowCursor = &relationSideEffectMatrix1402[row * kNationSlotCount];
  short* colCursor = &relationSideEffectMatrix1402[row];
  do {
    *rowCursor = 0;
    *colCursor = 0;
    ++rowCursor;
    colCursor += kNationSlotCount;
    --remaining;
  } while (remaining != 0);

  int terrainRecord = reinterpret_cast<int>(g_apTerrainTypeDescriptorTable[row]);
  if (terrainRecord == 0) {
    return;
  }
  if (*reinterpret_cast<short*>(terrainRecord + 0xe) <= 199) {
    return;
  }

  short decodedSlot = DecodeTerrainDescriptorNationSlotForAdjacency(terrainRecord);
  relationSideEffectMatrix1402[row * kNationSlotCount + decodedSlot] = 2;

  decodedSlot = DecodeTerrainDescriptorNationSlotForAdjacency(terrainRecord);
  relationSideEffectMatrix1402[decodedSlot * kNationSlotCount + row] = 2;
}

// FUNCTION: IMPERIALISM 0x004ef040
void TDiplomacyMgr::Free() {
  if (pendingWarTransitionQueue18d4 != 0) {
    pendingWarTransitionQueue18d4->ReleasePtrList();
    pendingWarTransitionQueue18d4 = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004ef080
void TDiplomacyMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(relationStandingScoreMatrix79c, sizeof(relationStandingScoreMatrix79c));
  stream->ReadBytes(relationPropagationMatrixBbe, sizeof(relationPropagationMatrixBbe));
  stream->ReadBytes(relationTurnStampMatrixFe0, sizeof(relationTurnStampMatrixFe0));
}

// FUNCTION: IMPERIALISM 0x004ef2a0
void TDiplomacyMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(relationStandingScoreMatrix79c, sizeof(relationStandingScoreMatrix79c));
  stream->WriteBytesSlot78(relationPropagationMatrixBbe, sizeof(relationPropagationMatrixBbe));
  stream->WriteBytesSlot78(relationTurnStampMatrixFe0, sizeof(relationTurnStampMatrixFe0));
}

// FUNCTION: IMPERIALISM 0x004ef540
bool TDiplomacyMgr::IsNationPairAtWar(NationSlot sourceNationSlot, NationSlot targetNationSlot) {
  if ((g_apTerrainTypeDescriptorTable[sourceNationSlot] != 0) &&
      (g_apTerrainTypeDescriptorTable[targetNationSlot] != 0)) {
    return GetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot) ==
           kDiplomacyRelationshipWar;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004ef590
bool TDiplomacyMgr::IsNationPairRelationTurnStampOutOfDate(int sourceNationSlot,
                                                           int targetNationSlot) {
  if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) == 0) {
    return false;
  }
  short currentTurn = g_pSimMgr->GetEconomicTurn();
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  return relationTurnStampMatrixFe0[source * kNationSlotCount + target] != currentTurn;
}

// FUNCTION: IMPERIALISM 0x004ef600
bool TDiplomacyMgr::HasAnyWarRelationForNation(int sourceNationSlot) {
  int targetNationSlot = 0;
  do {
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      return true;
    }
    targetNationSlot++;
  } while (targetNationSlot < 0x17);
  return false;
}

// FUNCTION: IMPERIALISM 0x004ef650
bool TDiplomacyMgr::HasAnyWarRelationTurnStampOutOfDateForNation(int sourceNationSlot) {
  int targetNationSlot = 0;
  do {
    if (IsNationPairRelationTurnStampOutOfDate(sourceNationSlot, targetNationSlot) != 0) {
      return true;
    }
    targetNationSlot++;
  } while (targetNationSlot < 0x17);
  return false;
}

// FUNCTION: IMPERIALISM 0x004ef6a0
bool TDiplomacyMgr::IsSpecialRelationSourceForMinorNationSlot(int nationSlot, int minorNationSlot) {
  return specialRelationSourceSlots1894[static_cast<short>(minorNationSlot) - 7] ==
         static_cast<short>(nationSlot);
}

// FUNCTION: IMPERIALISM 0x004ef6d0
bool TDiplomacyMgr::IsSpecialRelationTargetForMinorNationSlot(int nationSlot, int minorNationSlot) {
  return specialRelationTargetSlots18b4[static_cast<short>(minorNationSlot) - 7] ==
         static_cast<short>(nationSlot);
}

// FUNCTION: IMPERIALISM 0x004ef700
bool TDiplomacyMgr::ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(int sourceNationSlot,
                                                                             int targetNationSlot,
                                                                             eDipAction action) {
  bool isValid = false;
  short source = static_cast<short>(sourceNationSlot);
  short target = static_cast<short>(targetNationSlot);
  if (target == source) {
    ReadGlobalTDiplomacyTurnStateManager()->proposalArrayMode18d8 = 0xe;
    return isValid;
  }

  TCountry* targetTerrain = g_apTerrainTypeDescriptorTable[target];
  short targetTerrainOwner = targetTerrain->encodedNationSlot;
  if (targetTerrainOwner != -1) {
    if (targetTerrainOwner >= 200) {
      proposalArrayMode18d8 = 0xc;
      return isValid;
    }
    proposalArrayMode18d8 = 0xd;
    return isValid;
  }

  int pairIndex = source * kNationSlotCount + target;
  switch (action) {
  case kDipActionJoinEmpire:
    if (relationSideEffectMatrix1402[pairIndex] != 2) {
      proposalArrayMode18d8 = 1;
      return isValid;
    }
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (target < 7) {
      proposalArrayMode18d8 = 0x12;
      return isValid;
    }
    break;
  case kDipActionAlliance:
    if (target > 6) {
      proposalArrayMode18d8 = 3;
      return isValid;
    }
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (GetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot) ==
        kDiplomacyRelationshipAlliance) {
      proposalArrayMode18d8 = 0x11;
      return isValid;
    }
    break;
  case kDipActionNonAggressionPact:
    if (relationSideEffectMatrix1402[pairIndex] != 2) {
      proposalArrayMode18d8 = 1;
      return isValid;
    }
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (GetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot) ==
        kDiplomacyRelationshipNonAggressionPact) {
      proposalArrayMode18d8 = 0x10;
      return isValid;
    }
    if (target < 7) {
      proposalArrayMode18d8 = 0xf;
      return isValid;
    }
    break;
  case kDipActionPeaceTreaty:
    if (IsNationPairRelationTurnStampOutOfDate(sourceNationSlot, targetNationSlot) == 0) {
      proposalArrayMode18d8 = 5;
      return isValid;
    }
    break;
  case kDipActionDeclareWar:
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 6;
      return isValid;
    }
    break;
  case kDipActionOneTimeGrant:
  case kDipActionRecurringGrant:
    if (relationSideEffectMatrix1402[pairIndex] < 2) {
      proposalArrayMode18d8 = 1;
      return isValid;
    }
    break;
  case kDipActionTradeSubsidy:
  case kDipActionTradePolicy:
    if (relationSideEffectMatrix1402[pairIndex] == 0) {
      proposalArrayMode18d8 = 7;
      return isValid;
    }
    break;
  case kDipActionBoycott:
    if (GetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot) ==
        kDiplomacyRelationshipAlliance) {
      proposalArrayMode18d8 = 8;
      return isValid;
    }
    break;
  case kDipActionBuildConsulate:
    if (relationSideEffectMatrix1402[pairIndex] != 0) {
      proposalArrayMode18d8 = 9;
      return isValid;
    }
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (g_apNationStates[source]->treasuryValue10 < 500) {
      proposalArrayMode18d8 = 0x16;
      return isValid;
    }
    break;
  case kDipActionBuildEmbassy:
    if (relationSideEffectMatrix1402[pairIndex] == 0) {
      proposalArrayMode18d8 = 0xa;
      return isValid;
    }
    if (relationSideEffectMatrix1402[pairIndex] == 2) {
      proposalArrayMode18d8 = 0xb;
      return isValid;
    }
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (g_apNationStates[source]->treasuryValue10 < 5000) {
      proposalArrayMode18d8 = 0x15;
      return isValid;
    }
    break;
  }
  isValid = true;
  return isValid;
}

// FUNCTION: IMPERIALISM 0x004efc30
bool TDiplomacyMgr::HasAllianceGuardForNationPair(int nationSlot, int guardedNationSlot) {
  if (ReadGlobalTDiplomacyTurnStateManager()->HasAnyWarRelationForNation(nationSlot) == 0) {
    return false;
  }

  int primaryNationSlot = 0;
  do {
    if (IsNationPairAtWar(primaryNationSlot, nationSlot) != 0 &&
        IsNationPairAtWar(guardedNationSlot, primaryNationSlot) == 0) {
      return true;
    }
    primaryNationSlot++;
  } while (primaryNationSlot < 7);
  return false;
}

// FUNCTION: IMPERIALISM 0x004efcb0
void TDiplomacyMgr::SetStandingScoreSlot28(int sourceNationSlot, int targetNationSlot,
                                           int standingScore) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  int forwardIndex = source * kNationSlotCount + target;
  short* forwardScore = &relationStandingScoreMatrix79c[forwardIndex];
  short requestedScore = static_cast<short>(standingScore);
  if (requestedScore == *forwardScore) {
    return;
  }

  int clampedScore = requestedScore;
  if (requestedScore < 0) {
    clampedScore = 0;
  }
  if (requestedScore > 0xff &&
      static_cast<short>(sourceNationSlot) != static_cast<short>(targetNationSlot)) {
    clampedScore = 0xff;
  }
  if (requestedScore <= 0x31) {
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) == 0) {
      clampedScore = 0x32;
    } else {
      clampedScore = requestedScore;
    }
    if (static_cast<short>(clampedScore) < 0) {
      clampedScore = 0;
    }
  }

  *forwardScore = static_cast<short>(clampedScore);
  int reverseIndex = target * kNationSlotCount + source;
  relationStandingScoreMatrix79c[reverseIndex] = static_cast<short>(clampedScore);

  if (IsMajorNationSlot(sourceNationSlot) != 0) {
    int minorNationSlot = 7;
    TCountry** terrainCursor = &g_apTerrainTypeDescriptorTable[7];
    do {
      TMinor* terrain = static_cast<TMinor*>(*terrainCursor);
      if (terrain != 0 && terrain->HasMinorStandingLinkSlot5C(sourceNationSlot) != 0) {
        CopyDiplomacyStandingMatrixRowAndColumnSlot2c(minorNationSlot, sourceNationSlot);
      }
      terrainCursor++;
      minorNationSlot++;
    } while (reinterpret_cast<int>(terrainCursor) <
             reinterpret_cast<int>(&g_apTerrainTypeDescriptorTable[23]));
  }

  if (IsMajorNationSlot(targetNationSlot) != 0) {
    int minorNationSlot = 7;
    TCountry** terrainCursor = &g_apTerrainTypeDescriptorTable[7];
    do {
      TMinor* terrain = static_cast<TMinor*>(*terrainCursor);
      if (terrain != 0 && terrain->HasMinorStandingLinkSlot5C(targetNationSlot) != 0) {
        CopyDiplomacyStandingMatrixRowAndColumnSlot2c(minorNationSlot, targetNationSlot);
      }
      terrainCursor++;
      minorNationSlot++;
    } while (reinterpret_cast<int>(terrainCursor) <
             reinterpret_cast<int>(&g_apTerrainTypeDescriptorTable[23]));
  }
}

// FUNCTION: IMPERIALISM 0x004efe30
void TDiplomacyMgr::CopyDiplomacyStandingMatrixRowAndColumnSlot2c(int destinationNationSlot,
                                                                  int sourceNationSlot) {
  short* destinationColumnCursor =
      &relationStandingScoreMatrix79c[static_cast<short>(destinationNationSlot)];
  short* destinationRowCursor =
      &relationStandingScoreMatrix79c[static_cast<short>(destinationNationSlot) * kNationSlotCount];
  short* sourceRowCursor =
      &relationStandingScoreMatrix79c[static_cast<short>(sourceNationSlot) * kNationSlotCount];
  short* sourceColumnCursor = &relationStandingScoreMatrix79c[static_cast<short>(sourceNationSlot)];

  int remaining = kNationSlotCount;
  do {
    *destinationRowCursor = *sourceRowCursor;
    sourceRowCursor++;
    *destinationColumnCursor = *sourceColumnCursor;
    destinationRowCursor++;
    sourceColumnCursor += kNationSlotCount;
    destinationColumnCursor += kNationSlotCount;
    remaining--;
  } while (remaining != 0);
}

// FUNCTION: IMPERIALISM 0x004efeb0
void TDiplomacyMgr::ApplyPeaceRelationshipAndQueueEvent18ForTargetNation(int sourceNationSlot,
                                                                         int targetNationSlot,
                                                                         int updateMode) {
  SetNationPairDiplomacyRelationCodeFinal(sourceNationSlot, targetNationSlot,
                                          kDiplomacyRelationshipPeace);
  if (static_cast<char>(updateMode) == 1) {
    PropagateRelationSideEffectSlot80(sourceNationSlot, targetNationSlot, 0);
  }

  TMinor* targetTerrain =
      static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[static_cast<short>(targetNationSlot)]);
  if (targetTerrain != 0) {
    targetTerrain->NotifyActionSlot94(sourceNationSlot, 0x139);
    g_pNewsMgr->AddTreatyEvent(kInterNationEventPeaceRelationshipPropagated,
                               static_cast<short>(targetNationSlot),
                               static_cast<short>(sourceNationSlot), 0);
  }
}

// FUNCTION: IMPERIALISM 0x004eff40
void TDiplomacyMgr::PropagateRelationSideEffectSlot80(int sourceNationSlot, int targetNationSlot,
                                                      int updateMode) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  short sourceTargetStanding = relationStandingScoreMatrix79c[source * kNationSlotCount + target];

  if (static_cast<char>(updateMode) == 1) {
    if (sourceTargetStanding - 0x32 < 0x31) {
      SetStandingScoreSlot28(sourceNationSlot, targetNationSlot, sourceTargetStanding - 0x32);
    } else {
      SetStandingScoreSlot28(sourceNationSlot, targetNationSlot, 0x31);
    }
  } else {
    int adjustment = ((0x5a - sourceTargetStanding) * sourceTargetStanding) / 200;
    if (static_cast<short>(adjustment) < 0) {
      SetStandingScoreSlot28(sourceNationSlot, targetNationSlot, sourceTargetStanding + adjustment);
    }
  }

  int candidateNationSlot = 0;
  int candidateOrdinal = 0;
  TCountry** terrainCursor = g_apTerrainTypeDescriptorTable;
  do {
    TMinor* candidateTerrain = static_cast<TMinor*>(*terrainCursor);
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(candidateNationSlot) != 0 &&
        static_cast<short>(candidateNationSlot) != static_cast<short>(sourceNationSlot) &&
        static_cast<short>(candidateNationSlot) != static_cast<short>(targetNationSlot) &&
        candidateTerrain->encodedNationSlot == -1) {
      int divisorTier;
      if (IsMajorNationSlot(targetNationSlot) == 0) {
        if (IsMajorNationSlot(candidateNationSlot) == 0) {
          divisorTier =
              candidateTerrain->HasStandingPropagationBridgeSlot90(sourceNationSlot) != 0 ? 2 : 4;
        } else {
          divisorTier = 8;
        }
      } else {
        divisorTier = IsMajorNationSlot(candidateNationSlot) != 0 ? 4 : 8;
      }

      short currentStanding =
          relationStandingScoreMatrix79c[source * kNationSlotCount + candidateNationSlot];
      short targetCandidateStanding =
          relationStandingScoreMatrix79c[target * kNationSlotCount + candidateNationSlot];
      int candidateAdjustment =
          ((0x5a - targetCandidateStanding) * candidateOrdinal) / (divisorTier * 0x32);
      if (static_cast<char>(sourceNationSlot) == 0) {
        candidateAdjustment = static_cast<short>(candidateAdjustment) / 2;
      }

      short delta = static_cast<short>(candidateAdjustment);
      int appliedDelta = delta;
      if (currentStanding < 0x32) {
        if (delta > 0 && currentStanding + delta > 0x31) {
          appliedDelta = 0x31 - currentStanding;
        }
      } else if (currentStanding + delta < 0x32) {
        appliedDelta = 0x32 - currentStanding;
      }
      SetStandingScoreSlot28(sourceNationSlot, candidateNationSlot, currentStanding + appliedDelta);
    }

    candidateNationSlot++;
    candidateOrdinal++;
    terrainCursor++;
  } while (static_cast<short>(candidateNationSlot) <= 0x16);
}

// FUNCTION: IMPERIALISM 0x004f01e0
void TDiplomacyMgr::ApplyDiplomacyInterNationStatesForTurn() {
  // Pre-pass (unless localization phase 2): run the per-nation begin-turn slot 0x1c8
  // over the seven majors descending, gated on the nation's eligibility byte at +0xa0.
  if (g_pSimMgr->difficultyLevel != 2) {
    TGreatPower** nationCursor = &g_apNationStates[6];
    int remaining = 7;
    do {
      TGreatPower* nation = *nationCursor;
      if (nation != 0 && nation->diplomacyEligibilityA0 == 0) {
        nation->BeginTurnDiplomacyPrePassSlot1c8();
      }
      --nationCursor;
      --remaining;
    } while (remaining != 0);
  }

  // Four scratch shared strings held live across the pass (EH-RAII frame).
  ScratchSharedString scratch0;
  ScratchSharedString scratch1;
  ScratchSharedString scratch2;
  ScratchSharedString scratch3;

  if (g_pSimMgr->difficultyLevel == 2) {
    TGreatPower** nationCursor = &g_apNationStates[6];
    int remaining = 7;
    do {
      if (*nationCursor != 0) {
        (*nationCursor)->ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
      }
      --nationCursor;
      --remaining;
    } while (remaining != 0);
  } else {
    TGreatPower** nationCursor = g_apNationStates;
    int remaining = 7;
    do {
      if (*nationCursor != 0) {
        (*nationCursor)->ApplyTurnDiplomacyStateSlot1e0();
      }
      ++nationCursor;
      --remaining;
    } while (remaining != 0);

    int row = 0;     // major nation
    int rowBase = 0; // row * kNationSlotCount
    do {
      if (g_apTerrainTypeDescriptorTable[row] != 0) {
        int col = 0;     // paired terrain/minor index
        int colBase = 0; // col * kNationSlotCount
        int fieldOffset = 0xb2;
        do {
          if (g_apTerrainTypeDescriptorTable[col] != 0) {
            char* rowNation = reinterpret_cast<char*>(g_apNationStates[row]);
            short flag = *reinterpret_cast<short*>(rowNation + fieldOffset + 0x2e);
            if (flag != -1) {
              if (IsMajorNationSlot(col) != 0) {
                // arg0 is the constant 0 (held in [esp+0x10] across the loop in the original).
                g_apNationStates[col]->NotifyActionSlot94(0, flag);
              }
              g_apNationStates[row]->RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8(row);
            }
            short relationCode = *reinterpret_cast<short*>(rowNation + fieldOffset);
            if (relationCode != -1) {
              if (relationCode == 0x133) {
                relationSideEffectMatrix1402[rowBase + col] = 1;
                relationSideEffectMatrix1402[row + colBase] = 1;
                g_pNewsMgr->AddTreatyEvent(kInterNationEventTradeConsulateEstablished, row, col, 0);
              } else if (relationCode == 0x134) {
                relationSideEffectMatrix1402[rowBase + col] = 2;
                relationSideEffectMatrix1402[row + colBase] = 2;
                g_pNewsMgr->AddTreatyEvent(kInterNationEventEmbassyEstablished, row, col, 0);
              } else if (relationCode == kDiplomacyProposalDeclareWar) {
                if (IsNationPairAtWar(row, col) == 0) {
                  g_apNationStates[row]->QueueWarTransitionAndNotifyThirdPartyIfNeeded(col, 4, -1);
                }
              } else {
                static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[col])
                    ->ApplyTerrainDiplomacyRelationFlagSlot8c(
                        row, static_cast<DiplomacyRelationship>(relationCode));
              }
            }
          }
          ++col;
          fieldOffset += 2;
          colBase += kNationSlotCount;
        } while (static_cast<short>(col) < kNationSlotCount);
      }
      ++row;
      rowBase += kNationSlotCount;
    } while (static_cast<short>(row) < 7);
  }
}

// FUNCTION: IMPERIALISM 0x004f0590
void TDiplomacyMgr::SyncNationField790FromLocalizationStateId() {
  proposalDispatchCounter790 = g_pSimMgr->GetEconomicTurn();
}

// FUNCTION: IMPERIALISM 0x004f05c0
void TDiplomacyMgr::SelectPriorityNationIndicesForMinorCapabilityRows() {
  for (int i = 0; i < 7; i++) {
    if (g_apNationStates[i] != NULL) {
      g_apNationStates[i]->ApplyJoinEmpireMode2FinalizeNationNameState();
    }
  }

  if (g_pSimMgr && g_pSimMgr->multiplayerSessionRole == 2) {
    if (pendingWarTransitionQueue18d4) {
      pendingWarTransitionQueue18d4->ClearAndFreeAllPtrListRecords();
    }
    return;
  }

  for (int minorSlot = 7; minorSlot < 23; minorSlot++) {
    short bestOfferScore = 0x8b;
    int bestOfferNation = -1;
    bool isOfferTie = true;

    int bestRelationScore = 9000;
    int bestRelationNation = -1;
    bool isRelationTie = true;
    (void)isOfferTie;
    (void)isRelationTie;

    unsigned int randSeed1 = 0;
    unsigned int randSeed2 = 0;

    for (int gpSlot = 0; gpSlot < 7; gpSlot++) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<NationSlot>(gpSlot))) {
        short relationVal = relationStandingScoreMatrix79c[minorSlot * 23 + gpSlot];
        if (bestOfferScore < relationVal) {
          isOfferTie = false;
          bestOfferNation = gpSlot;
          bestOfferScore = relationVal;
        } else if (relationVal == bestOfferScore) {
          isOfferTie = true;
          if (!g_apTerrainTypeDescriptorTable[gpSlot]->IsEncodedNationSlotMinus200Equal(gpSlot)) {
            unsigned int rnd = (unsigned int)relationVal + 0x31 +
                               (unsigned int)g_pSimMgr->GetEconomicTurn() + gpSlot;
            if (rnd == 0)
              rnd = randSeed1;
            randSeed1 = rnd * 0x15a4e35 + 1;
            if ((randSeed1 >> 12) & 1) {
              bestOfferNation = gpSlot;
              bestOfferScore = relationVal;
            }
          } else {
            bestOfferNation = gpSlot;
            bestOfferScore = relationVal;
          }
        }

        int score = (200 - relationSideEffectMatrix1402[minorSlot * 23 + gpSlot]) * relationVal;
        if (bestRelationScore < score) {
          isRelationTie = false;
          bestRelationNation = gpSlot;
          bestRelationScore = score;
        } else if (score == bestRelationScore) {
          isRelationTie = true;
          if (!g_apTerrainTypeDescriptorTable[gpSlot]->IsEncodedNationSlotMinus200Equal(gpSlot)) {
            unsigned int rnd = (unsigned int)relationVal + 0x31 +
                               (unsigned int)g_pSimMgr->GetEconomicTurn() + gpSlot;
            if (rnd == 0)
              rnd = randSeed2;
            randSeed2 = rnd * 0x15a4e35 + 1;
            if ((randSeed2 >> 12) & 1) {
              bestRelationNation = gpSlot;
              bestRelationScore = score;
            }
          } else {
            bestRelationNation = gpSlot;
            bestRelationScore = score;
          }
        }
      }
    }

    if (bestOfferNation != -1) {
      specialRelationSourceSlots1894[minorSlot - 7] = static_cast<NationSlot>(bestOfferNation);
    }
    if (bestRelationNation != -1) {
      specialRelationTargetSlots18b4[minorSlot - 7] = static_cast<NationSlot>(bestRelationNation);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004f09c0
void TDiplomacyMgr::QueueNationPairWarTransition(int sourceNationSlot, int targetNationSlot) {
  WarTransitionPair pair;
  pair.sourceNationSlot = static_cast<short>(sourceNationSlot);
  pair.targetNationSlot = static_cast<short>(targetNationSlot);
  pendingWarTransitionQueue18d4->InsertCopiedRecordAtFrontOfPtrList(&pair);
  SetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot, kDiplomacyRelationshipWar,
                                     1);
}

// FUNCTION: IMPERIALISM 0x004f0a10
void TDiplomacyMgr::ProcessQueuedWarTransitions() {
  if (pendingWarTransitionQueue18d4->GetSize() != 0) {
    char propagatedTransition = 0;
    WarTransitionPair* pair =
        static_cast<WarTransitionPair*>(pendingWarTransitionQueue18d4->PeekFirstPtrListEntry());
    int targetNationSlot = pair->targetNationSlot;
    int sourceNationSlot = pair->sourceNationSlot;
    pendingWarTransitionQueue18d4->RemovePtrListEntryByOneBasedIndexAndFree(1);

    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) == 0) {
      SetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot,
                                         kDiplomacyRelationshipWar, 0);
    }

    static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[targetNationSlot])
        ->NotifyActionSlot94(sourceNationSlot, kDiplomacyProposalDeclareWar);

    g_pNewsMgr->AddTreatyEvent(kInterNationEventWarDeclaredAgainstSubject, targetNationSlot,
                               sourceNationSlot, 0);
    g_pNewsMgr->AddTreatyEvent(kInterNationEventWarDeclaredBySubject, sourceNationSlot,
                               targetNationSlot, 0);

    if (targetNationSlot < 7) {
      g_apNationStates[sourceNationSlot]->NotifyActionSlot94(targetNationSlot, 0xc8);
    }

    if (IsMajorNationSlot(targetNationSlot) == 0) {
      int ownerNationSlot = -1;
      TCountry* targetTerrain = g_apTerrainTypeDescriptorTable[targetNationSlot];
      bool isUnowned = (targetTerrain->encodedNationSlot == static_cast<short>(ownerNationSlot));
      if (isUnowned) {
        ownerNationSlot = SelectDiplomacyTargetNationFromCandidateSetSlot94(targetNationSlot, 1, 2);
      }

      if (ownerNationSlot > -1) {
        int transitionResult = g_apNationStates[ownerNationSlot]->HandleWarTransitionRequest(
            targetNationSlot, sourceNationSlot);
        propagatedTransition = (transitionResult == 2);
      }
    } else {
      int otherNationSlot = 0;
      TGreatPower** nationStateCursor = g_apNationStates;
      DiplomacyRelationshipStorage* targetRelationCursor =
          &relationPropagationMatrixBbe[targetNationSlot * kNationSlotCount];
      do {
        if (*targetRelationCursor == kDiplomacyRelationshipAlliance &&
            IsNationPairAtWar(otherNationSlot, sourceNationSlot) == 0) {
          int transitionResult =
              (*nationStateCursor)
                  ->HandleWarTransitionRequestWithRoleSwap(targetNationSlot, sourceNationSlot, 0);
          propagatedTransition = (transitionResult == 2);
        }
        ++nationStateCursor;
        ++otherNationSlot;
        ++targetRelationCursor;
      } while (nationStateCursor < &g_apNationStates_End);

      otherNationSlot = 0;
      nationStateCursor = g_apNationStates;
      DiplomacyRelationshipStorage* sourceRelationCursor =
          &relationPropagationMatrixBbe[sourceNationSlot * kNationSlotCount];
      do {
        if (*sourceRelationCursor == kDiplomacyRelationshipAlliance &&
            ReadGlobalTDiplomacyTurnStateManager()->IsNationPairAtWar(otherNationSlot,
                                                                      targetNationSlot) == 0) {
          int transitionResult =
              (*nationStateCursor)
                  ->HandleWarTransitionRequestWithRoleSwap(targetNationSlot, sourceNationSlot, 1);
          propagatedTransition = (transitionResult == 2);
        }
        ++nationStateCursor;
        ++otherNationSlot;
        ++sourceRelationCursor;
      } while (nationStateCursor < &g_apNationStates_End);
    }

    if (propagatedTransition == 0) {
      TNextTradeCommand* packet = new TNextTradeCommand();
      InitializeRangePairAndResetCursor(packet, kTurnEventTagNext, g_pGlobalUiRootController);
      g_pGlobalUiRootController->DispatchUiSelectionToHandler(packet);
    }
  } else {
    bool isMultiplayerHost = (g_pSimMgr->multiplayerSessionRole == 1);
    if (isMultiplayerHost) {
      g_pGameFlowState->EmitTurnEvent3Mode18WithActiveNation();
    } else {
      g_pSimMgr->StartNextPhase();
    }
  }
}

// FUNCTION: IMPERIALISM 0x004f0e20
void TDiplomacyMgr::RebuildDiplomacyStandingAndInfluenceMatrices(char forceOrMode) {
  bool forceFullClear = (forceOrMode == 2);
  if (relationCodeMatrix04[0] == 0) {
    InitializeDiplomacyStandingBaselineRandom();
  }
  if (forceFullClear) {
    memset(relationCodeMatrix04, 0, sizeof(relationCodeMatrix04));
  }

  int topNationSlot;
  int secondNationSlot;
  BuildMajorNationDiplomacyStandingRanking(&topNationSlot, &secondNationSlot);
  selectedTargetNationSlot786 = static_cast<short>(secondNationSlot);
  selectedSourceNationSlot784 = static_cast<short>(topNationSlot);
  int topPower = comparativePowerRows1824[topNationSlot][1];
  int secondPower = comparativePowerRows1824[secondNationSlot][1];

  int topSideScore[kNationSlotCount];
  int secondSideScore[kNationSlotCount];
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    TCountry* descriptor = g_apTerrainTypeDescriptorTable[nationSlot];
    if (descriptor == nullptr) {
      topSideScore[nationSlot] = rand() % 50 + 50;
      secondSideScore[nationSlot] = rand() % 50 + 50;
      continue;
    }
    short encodedSlot = descriptor->encodedNationSlot;
    if (encodedSlot < 100 || encodedSlot > 199) {
      topSideScore[nationSlot] =
          (relationStandingScoreMatrix79c[topNationSlot * kNationSlotCount + nationSlot] * 100 /
               255 +
           topPower) /
          2;
      secondSideScore[nationSlot] =
          (relationStandingScoreMatrix79c[secondNationSlot * kNationSlotCount + nationSlot] * 100 /
               255 +
           secondPower) /
          2;
    } else {
      short homeTile = static_cast<short>(descriptor->homeTileIndex);
      int ownerNation = g_pGlobalMapState->terrainStateTable[homeTile].ownerNationTag04;
      topSideScore[nationSlot] = (ownerNation == topNationSlot) ? 1 : rand() % 50 + 50;
      secondSideScore[nationSlot] = (ownerNation == secondNationSlot) ? 1 : rand() % 50 + 50;
    }
  }
  topSideScore[topNationSlot] = 100;
  secondSideScore[secondNationSlot] = 100;

  int topSideCount = 0;
  int secondSideCount = 0;
  int totalOwnedCount = 0;
  int maxResidual = 0;
  for (int tileIndex = 0; tileIndex < kDiplomacyPairMatrixEntries; ++tileIndex) {
    pendingPolicyTierMatrix484[tileIndex] = -1;
    Province* cityRecord = reinterpret_cast<Province*>(
        reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable) + tileIndex * 0xa8);
    int ownerNationCode = cityRecord->ownerNationCode00;
    if (ownerNationCode == -1) {
      continue;
    }

    int topScore;
    int secondScore;
    if (cityRecord->formerOwnerNationCode01 < 7) {
      topScore = (comparativePowerRows1824[topNationSlot][0] +
                  comparativePowerRows1824[topNationSlot][3]) /
                 2;
      secondScore = (comparativePowerRows1824[secondNationSlot][0] +
                     comparativePowerRows1824[secondNationSlot][3]) /
                    2;
    } else {
      topScore = topSideScore[ownerNationCode];
      secondScore = secondSideScore[ownerNationCode];
      if (ownerNationCode > 6 && cityRecord->linkedRegionCount > 0) {
        for (int i = 0; i < cityRecord->linkedRegionCount; ++i) {
          short linkedTile = cityRecord->linkedTileIndices42[i];
          int secondaryOwner =
              g_pGlobalMapState->terrainStateTable[linkedTile].secondaryOwnerNationTag18;
          if (secondaryOwner == topNationSlot) {
            topScore += 2;
          } else if (secondaryOwner == secondNationSlot) {
            secondScore += 2;
          }
        }
      }
    }

    ++totalOwnedCount;
    pendingPolicyCodeMatrix304[tileIndex] = -1;
    bool topSideWins =
        (ownerNationCode == topNationSlot) ||
        g_apTerrainTypeDescriptorTable[ownerNationCode]->IsEncodedNationSlotMinus200Equal(
            topNationSlot);
    bool secondSideWins =
        !topSideWins &&
        ((ownerNationCode == secondNationSlot) ||
         g_apTerrainTypeDescriptorTable[ownerNationCode]->IsEncodedNationSlotMinus200Equal(
             secondNationSlot));
    if (topSideWins) {
      ++topSideCount;
      pendingPolicyCodeMatrix304[tileIndex] = static_cast<signed char>(topNationSlot);
      pendingPolicyTierMatrix484[tileIndex] = 0;
    } else if (secondSideWins) {
      ++secondSideCount;
      pendingPolicyCodeMatrix304[tileIndex] = static_cast<signed char>(secondNationSlot);
      pendingPolicyTierMatrix484[tileIndex] = 0;
    } else {
      short threshold = relationCodeMatrix04[tileIndex];
      short delta;
      if (topScore < secondScore) {
        if (threshold <= secondScore - topScore) {
          ++secondSideCount;
          pendingPolicyCodeMatrix304[tileIndex] = static_cast<signed char>(secondNationSlot);
          delta = static_cast<short>((secondScore - topScore) - threshold);
          pendingPolicyTierMatrix484[tileIndex] = delta;
          if (maxResidual < delta) {
            maxResidual = delta;
          }
        }
      } else if (topScore - secondScore >= threshold) {
        ++topSideCount;
        pendingPolicyCodeMatrix304[tileIndex] = static_cast<signed char>(topNationSlot);
        delta = static_cast<short>((topScore - secondScore) - threshold);
        pendingPolicyTierMatrix484[tileIndex] = delta;
        if (maxResidual < delta) {
          maxResidual = delta;
        }
      }
    }
  }

  for (int fillIndex = 0; fillIndex < kDiplomacyPairMatrixEntries; ++fillIndex) {
    short value = pendingPolicyTierMatrix484[fillIndex];
    if (value == 0) {
      pendingPolicyTierMatrix484[fillIndex] = static_cast<short>(rand() % 15 + 1);
    } else if (value > 0) {
      pendingPolicyTierMatrix484[fillIndex] = static_cast<short>(maxResidual - value + 15);
    }
  }

  int neutralCount = totalOwnedCount - topSideCount - secondSideCount;
  selectionFlagsA788 = static_cast<short>(topSideCount);
  selectionFlagsB78a = static_cast<short>(secondSideCount);
  selectionFlagsC78c = static_cast<short>(neutralCount);

  int winnerNationSlot = -1;
  if (secondSideCount < topSideCount) {
    if (forceFullClear || topSideCount >= totalOwnedCount * 2 / 3) {
      winnerNationSlot = topNationSlot;
    } else if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(
                   static_cast<short>(topNationSlot)) &&
               g_apNationStates[topNationSlot]->field8d3 < '3') {
      g_apNationStates[topNationSlot]->SetNationPendingActionStateAndPayload(0xb, -1);
    }
  } else if (topSideCount < secondSideCount) {
    if (forceFullClear || secondSideCount >= totalOwnedCount * 2 / 3) {
      winnerNationSlot = secondNationSlot;
    } else if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(
                   static_cast<short>(secondNationSlot)) &&
               g_apNationStates[secondNationSlot]->field8d3 < '3') {
      g_apNationStates[secondNationSlot]->SetNationPendingActionStateAndPayload(0xb, -1);
    }
  } else if (forceFullClear) {
    winnerNationSlot = topNationSlot;
  }

  if (winnerNationSlot != -1) {
    lastProcessedNationSlot78e = static_cast<short>(winnerNationSlot);
  }
  if (g_pSimMgr->multiplayerSessionRole == 1) {
    g_pGameFlowState->EmitTurnEvent26DiplomacyMatrixSnapshot();
  }
}

// Seeds relationCodeMatrix04 with a per-city baseline value (indexed parallel to
// g_pGlobalMapState->cityScoreTable, not by nation pair): unowned cities (-1) are
// skipped; cities formerly held by a major power (formerOwnerNationCode01 < 7) get
// 14 + 3d6; everyone else gets 8 + 3x(rand() mod 4).
// FUNCTION: IMPERIALISM 0x004f1570
void TDiplomacyMgr::InitializeDiplomacyStandingBaselineRandom() {
  for (int cityIndex = 0; cityIndex < kDiplomacyPairMatrixEntries; ++cityIndex) {
    signed char formerOwner = g_pGlobalMapState->cityScoreTable[cityIndex].formerOwnerNationCode01;
    if (formerOwner == -1) {
      continue;
    }
    short baseline;
    if (formerOwner < 7) {
      baseline = 14;
      for (int i = 0; i < 3; ++i) {
        baseline = static_cast<short>(baseline + rand() % 6);
      }
    } else {
      baseline = 8;
      for (int i = 0; i < 3; ++i) {
        baseline = static_cast<short>(baseline + rand() % 4);
      }
    }
    relationCodeMatrix04[cityIndex] = baseline;
  }
}

// FUNCTION: IMPERIALISM 0x004f1630
void TDiplomacyMgr::BuildMajorNationDiplomacyStandingRanking(int* topNationSlot,
                                                             int* secondNationSlot) {
  RecomputeNationComparativePowerMetrics();

  int nationSlotOrder[7];
  int powerScore[7];
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    nationSlotOrder[nationSlot] = nationSlot;
    int sum = 0;
    if (g_apTerrainTypeDescriptorTable[nationSlot] != nullptr) {
      for (int metric = 0; metric < 4; ++metric) {
        sum += comparativePowerRows1824[nationSlot][metric];
      }
    }
    powerScore[nationSlot] = sum;
  }

  for (int i = 0; i < 6; ++i) {
    for (int j = i + 1; j < 7; ++j) {
      bool swap = false;
      if (powerScore[j] > powerScore[i] || (powerScore[j] == powerScore[i] && (rand() & 1) != 0)) {
        swap = true;
      }
      if (swap) {
        int scoreTmp = powerScore[i];
        powerScore[i] = powerScore[j];
        powerScore[j] = scoreTmp;
        int slotTmp = nationSlotOrder[i];
        nationSlotOrder[i] = nationSlotOrder[j];
        nationSlotOrder[j] = slotTmp;
      }
    }
  }

  *topNationSlot = nationSlotOrder[0];
  *secondNationSlot = nationSlotOrder[1];
}

// Rebuild the per-nation comparative-power rows (+0x1824): army, average bilateral
// relation standing, territory+tech combined, and commodity value, each normalized
// against the strongest eligible nation (0..100; territory/tech halves 0..50).
// FUNCTION: IMPERIALISM 0x004f1760
void TDiplomacyMgr::RecomputeNationComparativePowerMetrics() {
  int maxCommodity = 1;
  int maxTerritory = 1;
  int maxTech = 1;
  int maxRelation = 1;
  int maxArmy = 1;
  int territoryScore[7];
  int techScore[7];
  int i;
  for (i = 0; i < 7; i++) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) == 0) {
      continue;
    }
    int army = g_apNationStates[i]->ComputeNationNavyOrderWeightedMovementScore() + 0x1f4;
    comparativePowerRows1824[i][0] = army;
    if (army > maxArmy) {
      maxArmy = army;
    }
    int relation = g_apNationStates[i]->RecomputeNationComparativePowerMetrics_Impl();
    comparativePowerRows1824[i][1] = relation;
    if (relation > maxRelation) {
      maxRelation = relation;
    }
    int commodity = g_apNationStates[i]->SumCommodityRecordAccumulatedValues();
    comparativePowerRows1824[i][3] = commodity;
    if (commodity > maxCommodity) {
      maxCommodity = commodity;
    }
    int territory = g_apNationStates[i]->ownedRegionList->GetSize();
    territoryScore[i] = territory;
    if (territory > maxTerritory) {
      maxTerritory = territory;
    }
    TGreatPower* nation = g_apNationStates[i];
    int tech = (nation != 0 ? nation->city : 0)->productionSummary1d8->populationCount08;
    techScore[i] = tech;
    if (tech > maxTech) {
      maxTech = tech;
    }
  }
  for (i = 0; i < 7; i++) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) != 0) {
      comparativePowerRows1824[i][0] = comparativePowerRows1824[i][0] * 100 / maxArmy;
      comparativePowerRows1824[i][1] = comparativePowerRows1824[i][1] * 100 / maxRelation;
      comparativePowerRows1824[i][3] = comparativePowerRows1824[i][3] * 100 / maxCommodity;
      int territory = territoryScore[i] * 50 / maxTerritory;
      territoryScore[i] = territory;
      int tech = techScore[i] * 50 / maxTech;
      techScore[i] = tech;
      comparativePowerRows1824[i][2] = territory + tech;
    } else {
      comparativePowerRows1824[i][0] = 0;
      comparativePowerRows1824[i][1] = 0;
      comparativePowerRows1824[i][2] = 0;
      comparativePowerRows1824[i][3] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004f1970
bool TDiplomacyMgr::HasNationPairNeedLevel300(int sourceNation, int targetNation) {
  int source = static_cast<short>(sourceNation);
  int target = static_cast<short>(targetNation);
  TCountry* sourceCountry = g_apTerrainTypeDescriptorTable[source];
  if (sourceCountry->needLevelByNation[target] == 300) {
    return true;
  }
  TCountry* targetCountry = g_apTerrainTypeDescriptorTable[target];
  return targetCountry->needLevelByNation[source] == 300;
}

// FUNCTION: IMPERIALISM 0x004f19c0
DiplomacyRelationshipNotch TDiplomacyMgr::GetRelationshipNotch(NationSlot sourceNationSlot,
                                                               NationSlot targetNationSlot) {
  int source = sourceNationSlot;
  int target = targetNationSlot;
  short standingScore = relationStandingScoreMatrix79c[source * kNationSlotCount + target];
  if (standingScore <= 0x14) {
    return kDiplomacyRelationshipNotchThrough20;
  }
  if (standingScore <= 0x31) {
    return kDiplomacyRelationshipNotchThrough49;
  }
  if (standingScore <= 0x4f) {
    return kDiplomacyRelationshipNotchThrough79;
  }
  if (standingScore <= 0x64) {
    return kDiplomacyRelationshipNotchThrough100;
  }
  if (standingScore <= 0x87) {
    return kDiplomacyRelationshipNotchThrough135;
  }
  if (standingScore <= 0xaa) {
    return kDiplomacyRelationshipNotchThrough170;
  }
  if (standingScore <= 0xcd) {
    return kDiplomacyRelationshipNotchThrough205;
  }
  if (standingScore <= 0xf0) {
    return kDiplomacyRelationshipNotchThrough240;
  }
  return kDiplomacyRelationshipNotchAbove240;
}

// FUNCTION: IMPERIALISM 0x004f1a80
void TDiplomacyMgr::LoadTreatyNameForNationPairIfDisplayable(NationSlot sourceNationSlot,
                                                             NationSlot targetNationSlot,
                                                             CString* treatyName) {
  DiplomacyRelationship relationship = static_cast<DiplomacyRelationship>(
      relationPropagationMatrixBbe[sourceNationSlot * kNationSlotCount + targetNationSlot]);
  switch (relationship) {
  case kDiplomacyRelationshipAlliance:
  case kDiplomacyRelationshipNonAggressionPact:
  case kDiplomacyRelationshipPeace:
  case kDiplomacyRelationshipWar:
    g_pSimMgr->GetString(0x2714, relationship, treatyName);
    break;
  }
}

// FUNCTION: IMPERIALISM 0x004f1b10
DiplomacyRelationshipStorage
TDiplomacyMgr::GetNationPairDiplomacyRelationCode(NationSlot sourceNationSlot,
                                                  NationSlot targetNationSlot) {
  return (&relationPropagationMatrixBbe[sourceNationSlot * kNationSlotCount])[targetNationSlot];
}

// FUNCTION: IMPERIALISM 0x004f1b40
void TDiplomacyMgr::SetNationPairDiplomacyRelationCodeFinal(int sourceNationSlot,
                                                            int targetNationSlot,
                                                            DiplomacyRelationship relationship) {
  SetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot, relationship, 1);
}

// FUNCTION: IMPERIALISM 0x004f1b70
void TDiplomacyMgr::SetNationPairDiplomacyRelationCode(int sourceNationSlot, int targetNationSlot,
                                                       DiplomacyRelationship relationship,
                                                       int updateMode) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  int forwardIndex = source * kNationSlotCount + target;
  DiplomacyRelationshipStorage newRelationship =
      static_cast<DiplomacyRelationshipStorage>(relationship);
  if (newRelationship == relationPropagationMatrixBbe[forwardIndex]) {
    return;
  }

  relationPropagationMatrixBbe[forwardIndex] = newRelationship;
  int reverseIndex = target * kNationSlotCount + source;
  relationPropagationMatrixBbe[reverseIndex] = newRelationship;
  relationTurnStampMatrixFe0[forwardIndex] = g_pSimMgr->GetEconomicTurn();
  relationTurnStampMatrixFe0[reverseIndex] = g_pSimMgr->GetEconomicTurn();

  if (IsMajorNationSlot(sourceNationSlot) != 0) {
    g_apNationStates[source]->DispatchNationDiplomacySlotActionByMode(target, relationship);
  }
  if (IsMajorNationSlot(targetNationSlot) != 0) {
    g_apNationStates[target]->DispatchNationDiplomacySlotActionByMode(source, relationship);
  }

  switch (newRelationship) {
  case 0:
  case 1:
    break;
  case kDiplomacyRelationshipAlliance:
    g_pNewsMgr->AddTreatyEvent(kInterNationEventAllianceRelationshipEstablished, source, target, 0);
    return;
  case kDiplomacyRelationshipNonAggressionPact:
    SetStandingScoreSlot28(sourceNationSlot, targetNationSlot,
                           relationStandingScoreMatrix79c[forwardIndex] + 10);
    break;
  case kDiplomacyRelationshipPeace:
    if (relationStandingScoreMatrix79c[forwardIndex] <= 0x31) {
      SetStandingScoreSlot28(sourceNationSlot, targetNationSlot, 0x32);
    }
    if (IsMajorNationSlot(sourceNationSlot) != 0) {
      g_apNationStates[source]->NotifyAllianceSlot214(target);
    }
    if (IsMajorNationSlot(targetNationSlot) != 0) {
      g_apNationStates[target]->NotifyAllianceSlot214(source);
    }
    if ((IsMajorNationSlot(sourceNationSlot) != 0) && (IsMajorNationSlot(targetNationSlot) != 0)) {
      relationSideEffectMatrix1402[forwardIndex] = 2;
      relationSideEffectMatrix1402[reverseIndex] = 2;
      static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[source])
          ->SetDiplomacyStandingSlot48(targetNationSlot, 100);
      static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[target])
          ->SetDiplomacyStandingSlot48(sourceNationSlot, 100);
      return;
    }
    break;
  case kDiplomacyRelationshipJoinedEmpire:
    SetStandingScoreSlot28(sourceNationSlot, targetNationSlot, 0xff);
    break;
  case kDiplomacyRelationshipWar: {
    TMinor* sourceTerrain = static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[source]);
    TMinor* targetTerrain = static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[target]);
    if ((sourceTerrain->encodedNationSlot == -1) && (targetTerrain->encodedNationSlot < 200)) {
      g_pNewsMgr->AddTreatyEvent(kInterNationEventWarWithIndependentMinor, source, target, 0);
    }
    sourceTerrain->SetDiplomacyStandingSlot48(targetNationSlot, 300);
    targetTerrain->SetDiplomacyStandingSlot48(sourceNationSlot, 300);
    relationSideEffectMatrix1402[forwardIndex] = 0;
    relationSideEffectMatrix1402[reverseIndex] = 0;
    if (IsMajorNationSlot(sourceNationSlot) != 0) {
      g_apNationStates[source]->PruneInvalidTrackedEntriesAndNotifyOwner();
    }
    if (IsMajorNationSlot(targetNationSlot) != 0) {
      g_apNationStates[target]->PruneInvalidTrackedEntriesAndNotifyOwner();
    }
    if (static_cast<char>(updateMode) == 1) {
      PropagateRelationSideEffectSlot80(sourceNationSlot, targetNationSlot, 1);
      return;
    }
  } break;
  }
}

// FUNCTION: IMPERIALISM 0x004f1f20
short TDiplomacyMgr::LookupOrderCompatibilityMatrixValue(int sourceNationSlot,
                                                         int targetNationSlot) {
  short* row = &relationSideEffectMatrix1402[sourceNationSlot * kNationSlotCount];
  return row[targetNationSlot];
}

// FUNCTION: IMPERIALISM 0x004f1f50
bool TDiplomacyMgr::IsMajorNationSlot(int nationSlot) {
  return static_cast<short>(nationSlot) < 7;
}

// FUNCTION: IMPERIALISM 0x004f1f70
void TDiplomacyMgr::BuildRelationshipListSlot88(NationSlot sourceNationSlot, short primaryOnlyFlag,
                                                void* listHandle) {
  // The slot signature is the native void* handle; recover the common list base once
  // (InsertCopiedRecordSortedByComparator is a TIndexAndRankList virtual, shared by every sorted-list leaf).
  TIndexAndRankList* list = static_cast<TIndexAndRankList*>(listHandle);
  short candidateNationSlot;
  short lastNationSlot;
  if (primaryOnlyFlag == 0) {
    candidateNationSlot = 7;
    lastNationSlot = 0x16;
  } else {
    candidateNationSlot = 0;
    lastNationSlot = 6;
  }

  if (candidateNationSlot > lastNationSlot) {
    return;
  }

  int candidateIndex = static_cast<short>(candidateNationSlot);
  TCountry** terrainCursor = &g_apTerrainTypeDescriptorTable[candidateIndex];
  do {
    TCountry* terrain = *terrainCursor;
    if (terrain != 0) {
      // Materialized bool in the original (xor/sete/test), separate from the
      // slot-inequality test.
      char isUnclaimed = terrain->encodedNationSlot == -1;
      if (isUnclaimed && candidateNationSlot != sourceNationSlot) {
        RelationshipRankEntry entry;
        entry.nationSlot = candidateNationSlot;
        int source = sourceNationSlot;
        entry.standingScore =
            relationStandingScoreMatrix79c[source * kNationSlotCount + candidateIndex];
        list->InsertCopiedRecordSortedByComparator(&entry);
      }
    }
    candidateNationSlot++;
    candidateIndex++;
    terrainCursor++;
  } while (candidateNationSlot <= lastNationSlot);
}

// FUNCTION: IMPERIALISM 0x004f2050
int TDiplomacyMgr::CountMajorAllianceRelationsSlot8c(int sourceNationSlot) {
  int allianceCount = 0;
  DiplomacyRelationshipStorage* relationCursor =
      &relationPropagationMatrixBbe[sourceNationSlot * kNationSlotCount];
  int remainingMajorNationSlots = 7;
  do {
    if (*relationCursor == kDiplomacyRelationshipAlliance) {
      allianceCount++;
    }
    relationCursor++;
    remainingMajorNationSlots--;
  } while (remainingMajorNationSlots != 0);
  return allianceCount;
}

// FUNCTION: IMPERIALISM 0x004f2090
int TDiplomacyMgr::GetNthAlliedMajorNationSlot90(int nthAllianceIndex, int sourceNationSlot) {
  int allianceOrdinal = 0;
  int candidateNationSlot = 0;
  do {
    if (allianceOrdinal == nthAllianceIndex + 1) {
      return candidateNationSlot - 1;
    }
    if (relationPropagationMatrixBbe[sourceNationSlot * kNationSlotCount + candidateNationSlot] ==
        kDiplomacyRelationshipAlliance) {
      allianceOrdinal++;
    }
    candidateNationSlot++;
  } while (candidateNationSlot < 7);
  return candidateNationSlot - 1;
}

// FUNCTION: IMPERIALISM 0x004f2100
int TDiplomacyMgr::SelectNationSlotFromCollectedStandingEntriesSlot98(int sourceNationSlot,
                                                                      int primaryOnlyFlag) {
  TSortedByRelationshipList* list = new TSortedByRelationshipList();
  list->recordSize14 = 4;
  BuildRelationshipListSlot88(sourceNationSlot, static_cast<char>(primaryOnlyFlag), list);
  if (list->GetSize() < 1) {
    return -1;
  }

  RelationshipRankEntry* entry =
      static_cast<RelationshipRankEntry*>(list->GetPtrListEntryByOneBasedIndex(list->GetSize()));
  int nationSlot = entry->nationSlot;
  if (list != 0) {
    list->ReleasePtrList();
  }
  return nationSlot;
}

// FUNCTION: IMPERIALISM 0x004f21f0
int TDiplomacyMgr::SelectDiplomacyTargetNationFromCandidateSetSlot94(int sourceNationSlot,
                                                                     int primaryOnlyFlag,
                                                                     int sideEffectCode) {
  if (static_cast<short>(sideEffectCode) == 0) {
    return SelectNationSlotFromCollectedStandingEntriesSlot98(sourceNationSlot, primaryOnlyFlag);
  }

  TSortedByRelationshipList* list = new TSortedByRelationshipList();
  list->recordSize14 = 4;
  BuildRelationshipListSlot88(sourceNationSlot, static_cast<char>(primaryOnlyFlag), list);
  int entryIndex = list->GetSize();
  if (entryIndex < 1) {
    return -1;
  }

  int matchedNationSlot = -1;
  while (entryIndex > 0 && matchedNationSlot == -1) {
    RelationshipRankEntry* entry =
        static_cast<RelationshipRankEntry*>(list->GetPtrListEntryByOneBasedIndex(entryIndex));
    int candidateNationSlot = entry->nationSlot;
    int source = static_cast<short>(sourceNationSlot);
    if (relationSideEffectMatrix1402[source * kNationSlotCount + candidateNationSlot] ==
        static_cast<short>(sideEffectCode)) {
      matchedNationSlot = candidateNationSlot;
    }
    entryIndex--;
  }

  if (list != 0) {
    list->ReleasePtrList();
  }
  return matchedNationSlot;
}

// FUNCTION: IMPERIALISM 0x004f24a0
void TDiplomacyMgr::RebuildMinorNationDispositionLookupTables(int nationCode) {
  for (int auxIndex = 0; auxIndex < 16; ++auxIndex) {
    TMinor* candidate = g_apNationAuxRuntimeStateSlots[auxIndex];
    if (!candidate->IsEncodedNationSlotMinus200Equal(nationCode)) {
      continue;
    }
    candidate->ApplyJoinEmpireMode2FinalizeNationNameState();

    TMinor* capabilityObject = g_apMinorNationCapabilityObjects[auxIndex];
    short minorSlot = static_cast<short>(7 + auxIndex);

    for (int majorSlot = 0; majorSlot < 7; ++majorSlot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(majorSlot)) {
        relationStandingScoreMatrix79c[majorSlot * kNationSlotCount + minorSlot] = 0x5a;
        relationStandingScoreMatrix79c[minorSlot * kNationSlotCount + majorSlot] = 0x5a;
        relationPropagationMatrixBbe[majorSlot * kNationSlotCount + minorSlot] =
            kDiplomacyRelationshipPeace;
        relationPropagationMatrixBbe[minorSlot * kNationSlotCount + majorSlot] =
            kDiplomacyRelationshipPeace;
      }
    }

    for (int otherMinorSlot = 7; otherMinorSlot < kNationSlotCount; ++otherMinorSlot) {
      short standingValue;
      DiplomacyRelationshipStorage propagationValue;
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(otherMinorSlot)) {
        TMinor* otherMinorCandidate = g_apMinorNationCapabilityObjects[otherMinorSlot - 7];
        if (otherMinorCandidate->encodedNationSlot >= 200) {
          short normalizedSlot = capabilityObject->DecodeOwnerNationSlot();
          int lookupIndex = normalizedSlot * kNationSlotCount + minorSlot;
          standingValue = relationStandingScoreMatrix79c[lookupIndex];
          propagationValue = relationPropagationMatrixBbe[lookupIndex];
        } else if (capabilityObject->ReturnFalseNationStateCapabilityFlag90(
                       static_cast<short>(otherMinorSlot))) {
          standingValue = 0x96;
          propagationValue = kDiplomacyRelationshipPeace;
        } else {
          standingValue = 0x6e;
          propagationValue = kDiplomacyRelationshipPeace;
        }
      } else {
        standingValue = 0x5a;
        propagationValue = kDiplomacyRelationshipPeace;
      }
      relationStandingScoreMatrix79c[otherMinorSlot * kNationSlotCount + minorSlot] = standingValue;
      relationStandingScoreMatrix79c[minorSlot * kNationSlotCount + otherMinorSlot] = standingValue;
      relationPropagationMatrixBbe[otherMinorSlot * kNationSlotCount + minorSlot] =
          propagationValue;
      relationPropagationMatrixBbe[minorSlot * kNationSlotCount + otherMinorSlot] =
          propagationValue;
    }

    for (int notifySlot = 0; notifySlot < 7; ++notifySlot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(notifySlot)) {
        g_apNationStates[notifySlot]->SetTradePolicyTo(minorSlot, 100);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004f2760
TurnEvent2SyncPacket*
TDiplomacyMgr::BuildTurnEvent2ArraySyncPacketFromBufferAndRefreshBaselineCopy() {
  TurnEvent2SyncPacket* packet = BuildTurnEvent2ArraySyncPacketDeltaOrFull(
      0x89c, relationStandingScoreMatrix79c, relationMatrixBaselineCopy794);
  packet->flag20 = 0;
  if (relationMatrixBaselineCopy794 == 0) {
    relationMatrixBaselineSize798 = 0x1138;
    relationMatrixBaselineCopy794 = new short[0x89c];
  }
  memcpy(relationMatrixBaselineCopy794, relationStandingScoreMatrix79c,
         relationMatrixBaselineSize798);
  return packet;
}

// FUNCTION: IMPERIALISM 0x004f27f0
void TDiplomacyMgr::ApplyTurnEvent2SyncPacketToRelationMatrix(TurnEvent2SyncPacket* packet) {
  packet->ApplyEncodedDeltaPayloadToBufferByMode(relationStandingScoreMatrix79c);
}

// FUNCTION: IMPERIALISM 0x004f2820
char TDiplomacyMgr::BuildEmbassy(DiplomaticMissionLevelStorage missionLevel, int sourceNation,
                                 int targetNation) {
  relationSideEffectMatrix1402[sourceNation * kNationSlotCount + targetNation] = missionLevel;
  relationSideEffectMatrix1402[targetNation * kNationSlotCount + sourceNation] = missionLevel;
  InterNationEventKind eventKind = missionLevel == kDiplomaticMissionEmbassy
                                       ? kInterNationEventEmbassyEstablished
                                       : kInterNationEventTradeConsulateEstablished;
  g_pNewsMgr->AddTreatyEvent(eventKind, sourceNation, targetNation, 0);
  return 1;
}

// FUNCTION: IMPERIALISM 0x004f2970
void ByteSwapShortInPlace(unsigned char* bytes) {
  unsigned char firstByte = bytes[0];
  unsigned char secondByte = bytes[1];
  bytes[0] = secondByte;
  bytes[1] = firstByte;
}

// Read `shortCount` big-endian shorts from `stream` into `buffer` and byte-swap each pair
// in place, so the caller ends up with host-order shorts. A zero or negative count reads
// nothing back-to-front and skips the swap loop entirely.
// FUNCTION: IMPERIALISM 0x004f2a60
void ReadByteSwappedShortArrayFromStream(TStream* stream, unsigned char* buffer, int shortCount) {
  stream->ReadBytes(buffer, shortCount * 2);
  if (0 < shortCount) {
    do {
      unsigned char firstByte = buffer[0];
      buffer[0] = buffer[1];
      buffer[1] = firstByte;
      buffer = buffer + 2;
      shortCount = shortCount - 1;
    } while (shortCount != 0);
  }
}

// FUNCTION: IMPERIALISM 0x005449b0
TurnEvent2SyncPacket* __cdecl BuildTurnEvent2ArraySyncPacketDeltaOrFull(unsigned int shortCount,
                                                                        short* current,
                                                                        short* baseline) {
  bool sendFull = true;
  int differing = 0;
  if (baseline != 0) {
    if (0 < static_cast<int>(shortCount)) {
      short* cur = current;
      unsigned int remaining = shortCount;
      do {
        if (*cur != cur[baseline - current]) {
          ++differing;
        }
        ++cur;
        --remaining;
      } while (remaining != 0);
    }
    if (static_cast<unsigned int>(differing * 4) < shortCount * 2) {
      sendFull = false;
    }
  }
  if (sendFull) {
    int packetSize = shortCount * 2 + 0x24;
    TurnEvent2SyncPacket* packet =
        static_cast<TurnEvent2SyncPacket*>(static_cast<void*>(new unsigned char[packetSize]));
    packet->eventCode = 0;
    packet->fromNetworkId = 0;
    packet->toNetworkId = 0;
    packet->messageLength = 0;
    packet->messageLength = 0x1c;
    packet->pendingNationSlot = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
    packet->messageLength = packetSize;
    packet->eventCode = 2;
    packet->toNetworkId = 0;
    memcpy(packet->payload, current, shortCount * 2);
    packet->deltaKind21 = 0;
    return packet;
  }
  int packetSize = differing * 4 + 0x24;
  TurnEvent2SyncPacket* packet =
      static_cast<TurnEvent2SyncPacket*>(static_cast<void*>(new unsigned char[packetSize]));
  packet->eventCode = 0;
  packet->fromNetworkId = 0;
  packet->toNetworkId = 0;
  packet->messageLength = 0;
  packet->messageLength = 0x1c;
  short pendingSlot = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  packet->messageLength = packetSize;
  packet->pendingNationSlot = pendingSlot;
  packet->eventCode = 2;
  packet->toNetworkId = 0;
  packet->deltaKind21 = 2;
  short* out = packet->payload;
  short* cur = current;
  for (int i = 0; i < static_cast<int>(shortCount); ++i) {
    if (*cur != cur[baseline - current]) {
      out[0] = static_cast<short>(i);
      out[1] = *cur;
      out += 2;
    }
    ++cur;
  }
  return packet;
}
