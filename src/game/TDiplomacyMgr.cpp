#include "game/TDiplomacyMgr.h"
#include "game/global_data_tables.h"
#include "game/nation_slot_eligibility.h"
#include "game/TSimMgr.h"
#include "game/TIndexAndRankList.h"
#include "game/TSortedByRelationshipList.h"
#include "game/TSortedPtrList.h"
#include "game/CString.h"
#include "game/TGreatPower.h"
#include "game/TMinor.h"
#include "game/TNextTradeCommand.h"
#include "game/TInterNationEventQueueManager.h"
#include "game/TApplication.h"
#include "game/TStream.h"
#include "game/TMultiplayerMgr.h"
#include <new>

extern "C" CRuntimeClass TDiplomacyMgr_classRuntimeClass_00654cd0;

char IsNationSlotEligibleForEventProcessing(short nationSlot);

namespace {
const unsigned int kTurnEventTagNext = 0x4E655854;
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

struct RelationshipRankEntry {
  short nationSlot;
  short standingScore;
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
int TDiplomacyMgr::WrapperFor_IsNationSlotEligibleForEventProcessingAt413250(int nationSlot) {
  return IsNationSlotEligibleForEventProcessing(static_cast<short>(nationSlot));
}
// SYNTHETIC: IMPERIALISM 0x004ee650
// TDiplomacyMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ee6a0
// TDiplomacyMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDiplomacyMgr, TObject)

// FUNCTION: IMPERIALISM 0x004ee6c0
TDiplomacyMgr* TDiplomacyMgr::ConstructTDiplomacyTurnStateManager_Vtbl00654d90() {
  int zero = 0;
  queuedWarTransitionActive794 = zero;
  queuedWarTransitionPending798 = zero;
  proposalDispatchCounter790 = static_cast<short>(zero);
  lastProcessedNationSlot78e = static_cast<short>(-1);
  return this;
}

TDiplomacyMgr::TDiplomacyMgr() {}

// SYNTHETIC: IMPERIALISM 0x004ee700
// TDiplomacyMgr::`scalar deleting destructor'
TDiplomacyMgr::~TDiplomacyMgr() {}

// FUNCTION: IMPERIALISM 0x004ee7a0
void TDiplomacyMgr::InitializeTDiplomacyTurnStateManagerDefaults() {
  TSortedPtrList* queue = new TSortedPtrList();
  queue->relationType = 4;
  pendingWarTransitionQueue18d4 = queue;

  register int zero = 0;

  short* relationCode = relationCodeMatrix04;
  unsigned char* pendingPolicyCode = pendingPolicyCodeMatrix304;
  int pairCount = kDiplomacyPairMatrixEntries;

  do {
    *relationCode = static_cast<short>(zero);
    *pendingPolicyCode = 0xff;
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

// FUNCTION: IMPERIALISM 0x004eef50
void TDiplomacyMgr::ResetTerrainAdjacencyMatrixRowAndSymmetricLink(short nationSlot) {
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
    pendingWarTransitionQueue18d4->ReleaseSlot24();
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
char TDiplomacyMgr::IsNationPairAtWar(int sourceNationSlot, int targetNationSlot) {
  short source = static_cast<short>(sourceNationSlot);
  short target = static_cast<short>(targetNationSlot);
  if ((g_apTerrainTypeDescriptorTable[source] != 0) &&
      (g_apTerrainTypeDescriptorTable[target] != 0)) {
    return GetRelationTierSlot70(sourceNationSlot, targetNationSlot) == 6;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ef590
char TDiplomacyMgr::IsNationPairRelationTurnStampOutOfDate(int sourceNationSlot,
                                                           int targetNationSlot) {
  if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) == 0) {
    return 0;
  }
  short currentTurn = g_pSimMgr->GetTurnTickSlot3C();
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  return relationTurnStampMatrixFe0[source * kNationSlotCount + target] != currentTurn;
}

// FUNCTION: IMPERIALISM 0x004ef600
char TDiplomacyMgr::HasAnyWarRelationForNation(int sourceNationSlot) {
  int targetNationSlot = 0;
  do {
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      return 1;
    }
    targetNationSlot++;
  } while (targetNationSlot < 0x17);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ef650
char TDiplomacyMgr::HasAnyWarRelationTurnStampOutOfDateForNation(int sourceNationSlot) {
  int targetNationSlot = 0;
  do {
    if (HasOutdatedWarRelationSlot48(sourceNationSlot, targetNationSlot) != 0) {
      return 1;
    }
    targetNationSlot++;
  } while (targetNationSlot < 0x17);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ef6a0
char TDiplomacyMgr::IsNationSlotInPrimaryGroupA(int nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ef6d0
char TDiplomacyMgr::IsNationSlotInPrimaryGroupB(int nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ef700
char TDiplomacyMgr::ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(int sourceNationSlot,
                                                                             int targetNationSlot,
                                                                             int actionCode) {
  char isValid = 0;
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
  switch (actionCode) {
  case 2:
    if (relationSideEffectMatrix1402[pairIndex] != 2) {
      proposalArrayMode18d8 = 1;
      return isValid;
    }
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (target < 7) {
      proposalArrayMode18d8 = 0x12;
      return isValid;
    }
    break;
  case 3:
    if (target > 6) {
      proposalArrayMode18d8 = 3;
      return isValid;
    }
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (GetRelationTierSlot70(sourceNationSlot, targetNationSlot) == 2) {
      proposalArrayMode18d8 = 0x11;
      return isValid;
    }
    break;
  case 4:
    if (relationSideEffectMatrix1402[pairIndex] != 2) {
      proposalArrayMode18d8 = 1;
      return isValid;
    }
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (GetRelationTierSlot70(sourceNationSlot, targetNationSlot) == 3) {
      proposalArrayMode18d8 = 0x10;
      return isValid;
    }
    if (target < 7) {
      proposalArrayMode18d8 = 0xf;
      return isValid;
    }
    break;
  case 5:
    if (HasOutdatedWarRelationSlot48(sourceNationSlot, targetNationSlot) == 0) {
      proposalArrayMode18d8 = 5;
      return isValid;
    }
    break;
  case 6:
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 6;
      return isValid;
    }
    break;
  case 7:
  case 8:
    if (relationSideEffectMatrix1402[pairIndex] < 2) {
      proposalArrayMode18d8 = 1;
      return isValid;
    }
    break;
  case 9:
  case 10:
    if (relationSideEffectMatrix1402[pairIndex] == 0) {
      proposalArrayMode18d8 = 7;
      return isValid;
    }
    break;
  case 11:
    if (GetRelationTierSlot70(sourceNationSlot, targetNationSlot) == 2) {
      proposalArrayMode18d8 = 8;
      return isValid;
    }
    break;
  case 14:
    if (relationSideEffectMatrix1402[pairIndex] != 0) {
      proposalArrayMode18d8 = 9;
      return isValid;
    }
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (g_apNationStates[source]->treasuryValue10 < 500) {
      proposalArrayMode18d8 = 0x16;
      return isValid;
    }
    break;
  case 15:
    if (relationSideEffectMatrix1402[pairIndex] == 0) {
      proposalArrayMode18d8 = 0xa;
      return isValid;
    }
    if (relationSideEffectMatrix1402[pairIndex] == 2) {
      proposalArrayMode18d8 = 0xb;
      return isValid;
    }
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (g_apNationStates[source]->treasuryValue10 < 5000) {
      proposalArrayMode18d8 = 0x15;
      return isValid;
    }
    break;
  }
  isValid = 1;
  return isValid;
}

// FUNCTION: IMPERIALISM 0x004efc30
char TDiplomacyMgr::HasAllianceGuardSlot60(int nationSlot, int guardedNationSlot) {
  if (ReadGlobalTDiplomacyTurnStateManager()->HasAnyWarRelationForNation(nationSlot) == 0) {
    return 0;
  }

  int primaryNationSlot = 0;
  do {
    if (HasPolicyWithNationSlot44(primaryNationSlot, nationSlot) != 0 &&
        HasPolicyWithNationSlot44(guardedNationSlot, primaryNationSlot) == 0) {
      return 1;
    }
    primaryNationSlot++;
  } while (primaryNationSlot < 7);
  return 0;
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
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) == 0) {
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

  if (HasFlag84ForNationSlot84(sourceNationSlot) != 0) {
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

  if (HasFlag84ForNationSlot84(targetNationSlot) != 0) {
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
void TDiplomacyMgr::ApplyRelationCode4AndQueueEvent18ForTargetNation(int sourceNationSlot,
                                                                     int targetNationSlot,
                                                                     int updateMode) {
  SetRelationCodeSlot78Final(sourceNationSlot, targetNationSlot, 4);
  if (static_cast<char>(updateMode) == 1) {
    PropagateRelationSideEffectSlot80(sourceNationSlot, targetNationSlot, 0);
  }

  TMinor* targetTerrain =
      static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[static_cast<short>(targetNationSlot)]);
  if (targetTerrain != 0) {
    targetTerrain->NotifyActionSlot94(sourceNationSlot, 0x139);
    g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
        0x18, static_cast<short>(targetNationSlot), static_cast<short>(sourceNationSlot), 0);
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
    if (IsNationSlotEligibleForEventProcessing(candidateNationSlot) != 0 &&
        static_cast<short>(candidateNationSlot) != static_cast<short>(sourceNationSlot) &&
        static_cast<short>(candidateNationSlot) != static_cast<short>(targetNationSlot) &&
        candidateTerrain->encodedNationSlot == -1) {
      int divisorTier;
      if (HasFlag84ForNationSlot84(targetNationSlot) == 0) {
        if (HasFlag84ForNationSlot84(candidateNationSlot) == 0) {
          divisorTier =
              candidateTerrain->HasStandingPropagationBridgeSlot90(sourceNationSlot) != 0 ? 2 : 4;
        } else {
          divisorTier = 8;
        }
      } else {
        divisorTier = HasFlag84ForNationSlot84(candidateNationSlot) != 0 ? 4 : 8;
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
  if (g_pSimMgr->redrawEnabled != 2) {
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

  if (g_pSimMgr->redrawEnabled == 2) {
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
              if (HasFlag84ForNationSlot84(col) != 0) {
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
                g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x12, row, col,
                                                                                    0);
              } else if (relationCode == 0x134) {
                relationSideEffectMatrix1402[rowBase + col] = 2;
                relationSideEffectMatrix1402[row + colBase] = 2;
                g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x14, row, col,
                                                                                    0);
              } else if (relationCode == 0x131) {
                if (HasPolicyWithNationSlot44(row, col) == 0) {
                  g_apNationStates[row]->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(
                      col, 4, -1);
                }
              } else {
                static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[col])
                    ->ApplyTerrainDiplomacyRelationFlagSlot8c(row, relationCode);
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

// FUNCTION: IMPERIALISM 0x004f05c0
void TDiplomacyMgr::SelectPriorityNationIndicesForMinorCapabilityRows() {}

// FUNCTION: IMPERIALISM 0x004f09c0
void TDiplomacyMgr::QueueNationPairWarTransition(int sourceNationSlot, int targetNationSlot) {
  WarTransitionPair pair;
  pair.sourceNationSlot = static_cast<short>(sourceNationSlot);
  pair.targetNationSlot = static_cast<short>(targetNationSlot);
  pendingWarTransitionQueue18d4->PushPairSlot40(&pair);
  SetRelationCodeSlot74WithMode(sourceNationSlot, targetNationSlot, 6, 1);
}

// FUNCTION: IMPERIALISM 0x004f0a10
void TDiplomacyMgr::ProcessQueuedWarTransitions() {
  if (pendingWarTransitionQueue18d4->GetSize() != 0) {
    char propagatedTransition = 0;
    WarTransitionPair* pair =
        static_cast<WarTransitionPair*>(pendingWarTransitionQueue18d4->PeekFirstPairSlot34());
    int targetNationSlot = pair->targetNationSlot;
    int sourceNationSlot = pair->sourceNationSlot;
    pendingWarTransitionQueue18d4->RemoveFirstPairSlot30(1);

    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) == 0) {
      SetRelationCodeSlot74WithMode(sourceNationSlot, targetNationSlot, 6, 0);
    }

    static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[targetNationSlot])
        ->NotifyActionSlot94(sourceNationSlot, 0x131);

    g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(1, targetNationSlot,
                                                                        sourceNationSlot, 0);
    g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0, sourceNationSlot,
                                                                        targetNationSlot, 0);

    if (targetNationSlot < 7) {
      g_apNationStates[sourceNationSlot]->NotifyActionSlot94(targetNationSlot, 0xc8);
    }

    if (HasFlag84ForNationSlot84(targetNationSlot) == 0) {
      int ownerNationSlot = -1;
      TCountry* targetTerrain = g_apTerrainTypeDescriptorTable[targetNationSlot];
      bool isUnowned = (targetTerrain->encodedNationSlot == static_cast<short>(ownerNationSlot));
      if (isUnowned) {
        ownerNationSlot = SelectDiplomacyTargetNationFromCandidateSetSlot94(targetNationSlot, 1, 2);
      }

      if (ownerNationSlot > -1) {
        int transitionResult = g_apNationStates[ownerNationSlot]->CheckTransitionSlot27C(
            targetNationSlot, sourceNationSlot);
        propagatedTransition = (transitionResult == 2);
      }
    } else {
      int otherNationSlot = 0;
      TGreatPower** nationStateCursor = g_apNationStates;
      short* targetRelationCursor =
          &relationPropagationMatrixBbe[targetNationSlot * kNationSlotCount];
      do {
        if (*targetRelationCursor == 2 &&
            HasPolicyWithNationSlot44(otherNationSlot, sourceNationSlot) == 0) {
          int transitionResult =
              (*nationStateCursor)
                  ->PropagateWarTransitionSlot280(targetNationSlot, sourceNationSlot, 0);
          propagatedTransition = (transitionResult == 2);
        }
        ++nationStateCursor;
        ++otherNationSlot;
        ++targetRelationCursor;
      } while (reinterpret_cast<int>(nationStateCursor) <
               reinterpret_cast<int>(&g_apNationStates_End));

      otherNationSlot = 0;
      nationStateCursor = g_apNationStates;
      short* sourceRelationCursor =
          &relationPropagationMatrixBbe[sourceNationSlot * kNationSlotCount];
      do {
        if (*sourceRelationCursor == 2 &&
            ReadGlobalTDiplomacyTurnStateManager()->HasPolicyWithNationSlot44(
                otherNationSlot, targetNationSlot) == 0) {
          int transitionResult =
              (*nationStateCursor)
                  ->PropagateWarTransitionSlot280(targetNationSlot, sourceNationSlot, 1);
          propagatedTransition = (transitionResult == 2);
        }
        ++nationStateCursor;
        ++otherNationSlot;
        ++sourceRelationCursor;
      } while (reinterpret_cast<int>(nationStateCursor) <
               reinterpret_cast<int>(&g_apNationStates_End));
    }

    if (propagatedTransition == 0) {
      TNextTradeCommand* packet = new TNextTradeCommand();
      InitializeRangePairAndResetCursor(packet, kTurnEventTagNext, g_pGlobalUiRootController);
      g_pGlobalUiRootController->DispatchUiSelectionToHandler(packet);
    }
  } else {
    bool isLocalizationOne = (g_pSimMgr->redrawEnabled == 1);
    if (isLocalizationOne) {
      g_pGameFlowState->EmitTurnEvent3Mode18WithActiveNation();
    } else {
      g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
    }
  }
}

// FUNCTION: IMPERIALISM 0x004f0e20
void TDiplomacyMgr::RebuildDiplomacyStandingAndInfluenceMatrices() {}

// FUNCTION: IMPERIALISM 0x004f1570
void TDiplomacyMgr::InitializeDiplomacyStandingBaselineRandom() {}

// FUNCTION: IMPERIALISM 0x004f1630
void TDiplomacyMgr::BuildMajorNationDiplomacyStandingRanking() {}

// FUNCTION: IMPERIALISM 0x004f1970
char TDiplomacyMgr::HasState300LinkBetweenNationPair(int sourceNation, int targetNation) {
  (void)sourceNation;
  (void)targetNation;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f19c0
int TDiplomacyMgr::GetNationPairDiplomacyStandingTierCode(int sourceNationSlot,
                                                          int targetNationSlot) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  short standingScore = relationStandingScoreMatrix79c[source * kNationSlotCount + target];
  if (standingScore <= 0x14) {
    return 0;
  }
  if (standingScore <= 0x31) {
    return 1;
  }
  if (standingScore <= 0x4f) {
    return 2;
  }
  if (standingScore <= 0x64) {
    return 3;
  }
  if (standingScore <= 0x87) {
    return 4;
  }
  if (standingScore <= 0xaa) {
    return 5;
  }
  if (standingScore <= 0xcd) {
    return 6;
  }
  return (standingScore > 0xf0) + 7;
}

// FUNCTION: IMPERIALISM 0x004f1a80
void TDiplomacyMgr::ShowRelationCodeNoticeForNationPairIfRelevant(int sourceNation,
                                                                  int targetNation) {
  (void)sourceNation;
  (void)targetNation;
}

// FUNCTION: IMPERIALISM 0x004f1b10
short TDiplomacyMgr::GetNationPairDiplomacyRelationCode(int sourceNationSlot,
                                                        int targetNationSlot) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  return relationPropagationMatrixBbe[source * kNationSlotCount + target];
}

// FUNCTION: IMPERIALISM 0x004f1b40
void TDiplomacyMgr::SetNationPairDiplomacyRelationCodeFinal(int sourceNationSlot,
                                                            int targetNationSlot,
                                                            int relationCode) {
  SetRelationCodeSlot74WithMode(sourceNationSlot, targetNationSlot, relationCode, 1);
}

// FUNCTION: IMPERIALISM 0x004f1b70
void TDiplomacyMgr::SetNationPairDiplomacyRelationCode(int sourceNationSlot, int targetNationSlot,
                                                       int relationCode, int updateMode) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  int forwardIndex = source * kNationSlotCount + target;
  short newRelationCode = static_cast<short>(relationCode);
  if (newRelationCode == relationPropagationMatrixBbe[forwardIndex]) {
    return;
  }

  relationPropagationMatrixBbe[forwardIndex] = newRelationCode;
  int reverseIndex = target * kNationSlotCount + source;
  relationPropagationMatrixBbe[reverseIndex] = newRelationCode;
  relationTurnStampMatrixFe0[forwardIndex] = g_pSimMgr->GetTurnTickSlot3C();
  relationTurnStampMatrixFe0[reverseIndex] = g_pSimMgr->GetTurnTickSlot3C();

  if (HasFlag84ForNationSlot84(sourceNationSlot) != 0) {
    g_apNationStates[source]->DispatchNationDiplomacySlotActionByMode(target, relationCode);
  }
  if (HasFlag84ForNationSlot84(targetNationSlot) != 0) {
    g_apNationStates[target]->DispatchNationDiplomacySlotActionByMode(source, relationCode);
  }

  switch (newRelationCode) {
  case 0:
  case 1:
    break;
  case 2:
    g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x1a, source, target, 0);
    return;
  case 3:
    SetStandingScoreSlot28(sourceNationSlot, targetNationSlot,
                           relationStandingScoreMatrix79c[forwardIndex] + 10);
    break;
  case 4:
    if (relationStandingScoreMatrix79c[forwardIndex] <= 0x31) {
      SetStandingScoreSlot28(sourceNationSlot, targetNationSlot, 0x32);
    }
    if (HasFlag84ForNationSlot84(sourceNationSlot) != 0) {
      g_apNationStates[source]->NotifyAllianceSlot214(target);
    }
    if (HasFlag84ForNationSlot84(targetNationSlot) != 0) {
      g_apNationStates[target]->NotifyAllianceSlot214(source);
    }
    if ((HasFlag84ForNationSlot84(sourceNationSlot) != 0) &&
        (HasFlag84ForNationSlot84(targetNationSlot) != 0)) {
      relationSideEffectMatrix1402[forwardIndex] = 2;
      relationSideEffectMatrix1402[reverseIndex] = 2;
      static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[source])
          ->SetDiplomacyStandingSlot48(targetNationSlot, 100);
      static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[target])
          ->SetDiplomacyStandingSlot48(sourceNationSlot, 100);
      return;
    }
    break;
  case 5:
    SetStandingScoreSlot28(sourceNationSlot, targetNationSlot, 0xff);
    break;
  case 6: {
    TMinor* sourceTerrain = static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[source]);
    TMinor* targetTerrain = static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[target]);
    if ((sourceTerrain->encodedNationSlot == -1) && (targetTerrain->encodedNationSlot < 200)) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x19, source, target, 0);
    }
    sourceTerrain->SetDiplomacyStandingSlot48(targetNationSlot, 300);
    targetTerrain->SetDiplomacyStandingSlot48(sourceNationSlot, 300);
    relationSideEffectMatrix1402[forwardIndex] = 0;
    relationSideEffectMatrix1402[reverseIndex] = 0;
    if (HasFlag84ForNationSlot84(sourceNationSlot) != 0) {
      g_apNationStates[source]->PruneInvalidTrackedEntriesAndNotifyOwner();
    }
    if (HasFlag84ForNationSlot84(targetNationSlot) != 0) {
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
char TDiplomacyMgr::IsPrimaryNationSlotIndex(int nationSlot) {
  return static_cast<short>(nationSlot) < 7;
}

// FUNCTION: IMPERIALISM 0x004f1f70
void TDiplomacyMgr::BuildRelationshipListSlot88(int sourceNationSlot, int primaryOnlyFlag,
                                                void* listHandle) {
  // The slot signature is the native void* handle; recover the common list base once
  // (AddEntrySlot38 is a TIndexAndRankList virtual, shared by every sorted-list leaf).
  TIndexAndRankList* list = static_cast<TIndexAndRankList*>(listHandle);
  short candidateNationSlot;
  short lastNationSlot;
  if (static_cast<short>(primaryOnlyFlag) == 0) {
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
    if (terrain != 0 && terrain->encodedNationSlot == -1 &&
        candidateNationSlot != static_cast<short>(sourceNationSlot)) {
      RelationshipRankEntry entry;
      entry.nationSlot = candidateNationSlot;
      int source = static_cast<short>(sourceNationSlot);
      entry.standingScore =
          relationStandingScoreMatrix79c[source * kNationSlotCount + candidateIndex];
      list->AddEntrySlot38(&entry);
    }
    candidateNationSlot++;
    candidateIndex++;
    terrainCursor++;
  } while (candidateNationSlot <= lastNationSlot);
}

// FUNCTION: IMPERIALISM 0x004f2050
int TDiplomacyMgr::CountMajorAllianceRelationsSlot8c(int sourceNationSlot) {
  int allianceCount = 0;
  short* relationCursor = &relationPropagationMatrixBbe[sourceNationSlot * kNationSlotCount];
  int remainingMajorNationSlots = 7;
  do {
    if (*relationCursor == 2) {
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
        2) {
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
  list->relationType = 4;
  BuildRelationshipListSlot88(sourceNationSlot, static_cast<char>(primaryOnlyFlag), list);
  if (list->GetSize() < 1) {
    return -1;
  }

  RelationshipRankEntry* entry =
      static_cast<RelationshipRankEntry*>(list->GetEntrySlot2C(list->GetSize()));
  int nationSlot = entry->nationSlot;
  if (list != 0) {
    list->ReleaseSlot24();
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
  list->relationType = 4;
  BuildRelationshipListSlot88(sourceNationSlot, static_cast<char>(primaryOnlyFlag), list);
  int entryIndex = list->GetSize();
  if (entryIndex < 1) {
    return -1;
  }

  int matchedNationSlot = -1;
  while (entryIndex > 0 && matchedNationSlot == -1) {
    RelationshipRankEntry* entry =
        static_cast<RelationshipRankEntry*>(list->GetEntrySlot2C(entryIndex));
    int candidateNationSlot = entry->nationSlot;
    int source = static_cast<short>(sourceNationSlot);
    if (relationSideEffectMatrix1402[source * kNationSlotCount + candidateNationSlot] ==
        static_cast<short>(sideEffectCode)) {
      matchedNationSlot = candidateNationSlot;
    }
    entryIndex--;
  }

  if (list != 0) {
    list->ReleaseSlot24();
  }
  return matchedNationSlot;
}

// FUNCTION: IMPERIALISM 0x00581280
char IsNationSlotEligibleForEventProcessing(short nationSlot) {
  if (nationSlot == -1) {
    return 0;
  }

  TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[nationSlot];
  if (terrainDescriptor == 0) {
    return 0;
  }

  if (nationSlot < 7) {
    short profileType = terrainDescriptor->encodedNationSlot;
    if (profileType >= 100 && profileType <= 199) {
      return 0;
    }
  }

  return 1;
}
