#include "game/diplomacy_domain_types.h"
#include "game/ui_tags_military.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/military/NetMessage.h"
#include "game/net/TMultiplayerMgr.h"
#include <string.h>
#include "game/map/TIndexAndRankList.h"
#include "game/map/TMapMgr.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/core/CString.h"
#include "game/nation/TGreatPower.h"
#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
#include "game/city_ui/TLongintList.h"
#include "game/nation/TMinor.h"
#include "game/ui_widgets/TNextTradeCommand.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_core/TApplication.h"
#include "game/core/stream_byteswap.h"
#include "game/core/TStream.h"
#include <new>
#include <stdlib.h>

namespace {
const unsigned int kTurnEventTagNext = kControlTagNeXT;
struct ScratchSharedString {
  CString str;
  // NOOP: verified empty in original 0x004f0245 (the four construction sites
  // emit only CString::CString for the member; the wrapper body adds nothing)
  ScratchSharedString() {}
};
} // namespace

static __inline void InitializeNextTradeCommandForHandler(TNextTradeCommand* packet, int eventTag,
                                                          TApplication* owner) {
  packet->ICommand(eventTag, owner, 0, 0, 0);
}

static __inline TDiplomacyMgr* ReadGlobalTDiplomacyTurnStateManager() {
  return g_pDiplomacyTurnStateManager;
}

struct WarTransitionPair {
  short sourceNationSlot;
  short targetNationSlot;
};

// FUNCTION: IMPERIALISM 0x00413250
int TDiplomacyMgr::GetFavoriteTradePartner(int minorNationSlot) {
  int bestScore = 0;
  int selectedNation = -1;
  for (int majorNation = 0; majorNation < 7; ++majorNation) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(majorNation)) == 0) {
      continue;
    }

    int score = (200 - g_apNationStates[majorNation]->needLevelByNation[minorNationSlot]) *
                relationStandingScores[minorNationSlot * kNationSlotCount + majorNation];
    bool select = score > bestScore;
    if (score == bestScore) {
      select = g_apTerrainTypeDescriptorTable[minorNationSlot]->IsColonyOf(majorNation) != 0;
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
TDiplomacyMgr::TDiplomacyMgr() : relationMatrixBaselineCopy(0), relationMatrixBaselineSize(0) {
  lastDiplomaticEffortTurn = 0;
  lastProcessedNationSlot = -1;
}

// SYNTHETIC: IMPERIALISM 0x004ee700
// TDiplomacyMgr::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004ee730
TDiplomacyMgr::~TDiplomacyMgr() {}

// FUNCTION: IMPERIALISM 0x004ee7a0
void TDiplomacyMgr::InitializeTDiplomacyTurnStateManagerDefaults() {
  TSortedPtrList* queue = new TSortedPtrList();
  queue->recordSize14 = 4;
  pendingWarTransitionQueue = queue;

  register int zero = 0;

  short* relationCode = relationCodeMatrix;
  signed char* pendingPolicyCode = pendingPolicyCodeMatrix;
  int pairCount = kDiplomacyPairMatrixEntries;

  do {
    *relationCode = static_cast<short>(zero);
    *pendingPolicyCode = -1;
    ++relationCode;
    ++pendingPolicyCode;
    --pairCount;
  } while (pairCount != 0);

  congressLeadership.chairmanNationSlot = static_cast<short>(-1);
  congressLeadership.counterpartNationSlot = static_cast<short>(-1);
  congressSupport.chairmanSupportCount = static_cast<short>(zero);
  congressSupport.counterpartSupportCount = static_cast<short>(zero);
  congressSupport.neutralCount = static_cast<short>(zero);
  proposalArrayMode = static_cast<short>(zero);

  short* rowStart = relationTurnStampMatrix;
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
      relationSideEffectMatrix[forwardIndex] = 0;
      relationSideEffectMatrix[reverseIndex] = 0;

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
      relationStandingScores[forwardIndex] = standingScore;
      relationPropagationMatrix[forwardIndex] = kDiplomacyRelationshipPeace;
    }
  }

  for (sourceNation = 7; sourceNation < kNationSlotCount; ++sourceNation) {
    TMinor* sourceMinor = static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[sourceNation]);
    for (targetNation = 7; targetNation < kNationSlotCount; ++targetNation) {
      int pairIndex = sourceNation * kNationSlotCount + targetNation;
      short standingScore = 0x5a;
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(sourceNation)) !=
              0 &&
          g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(targetNation)) !=
              0) {
        standingScore =
            sourceMinor->IsInConsortiumWith(static_cast<short>(targetNation)) != 0 ? 0x96 : 0x6e;
      }
      relationStandingScores[pairIndex] = standingScore;
      relationPropagationMatrix[pairIndex] = kDiplomacyRelationshipPeace;
    }
  }

  for (sourceNation = 0; sourceNation < kNationSlotCount; ++sourceNation) {
    relationStandingScores[sourceNation * (kNationSlotCount + 1)] = 0xff;
  }

  for (sourceNation = 0; sourceNation < 7; ++sourceNation) {
    for (targetNation = 0; targetNation < 7; ++targetNation) {
      int forwardIndex = sourceNation * kNationSlotCount + targetNation;
      int reverseIndex = targetNation * kNationSlotCount + sourceNation;
      if (sourceNation == targetNation) {
        relationSideEffectMatrix[forwardIndex] = 0;
      } else {
        relationSideEffectMatrix[forwardIndex] = 2;
        relationSideEffectMatrix[reverseIndex] = 2;
      }
    }
  }

  for (sourceNation = 0; sourceNation < 0x10; ++sourceNation) {
    specialRelationSourceSlots[sourceNation] = -1;
    specialRelationTargetSlots[sourceNation] = -1;
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
          relationSideEffectMatrix[forwardIndex] = 1;
          relationSideEffectMatrix[reverseIndex] = 1;
          g_pNewsMgr->AddTreatyEvent(kInterNationEventTradeConsulateEstablished, sourceNation,
                                     targetNation, 0);
          relationStandingScores[forwardIndex] = 0x6e;
          relationStandingScores[reverseIndex] = 0x6e;
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
        relationSideEffectMatrix[forwardIndex] = 1;
        relationSideEffectMatrix[reverseIndex] = 1;
        g_pNewsMgr->AddTreatyEvent(kInterNationEventTradeConsulateEstablished, sourceNation,
                                   targetNation, 0);
        relationStandingScores[forwardIndex] = 0x6e;
        relationStandingScores[reverseIndex] = 0x6e;
      }
    }
  }

  if (g_pSimMgr->difficultyLevel == 4) {
    for (sourceNation = 0; sourceNation < 7; ++sourceNation) {
      if (g_apNationStates[sourceNation]->diplomacyEligibilityA0 == 0) {
        for (targetNation = 0; targetNation < 7; ++targetNation) {
          if (g_apNationStates[targetNation]->diplomacyEligibilityA0 == 0) {
            relationStandingScores[sourceNation * kNationSlotCount + targetNation] = 0x6e;
            relationStandingScores[targetNation * kNationSlotCount + sourceNation] = 0x6e;
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
    if (relationPropagationMatrix[row * kNationSlotCount + i] != kDiplomacyRelationshipWar ||
        g_apTerrainTypeDescriptorTable[row] == 0) {
      relationPropagationMatrix[row * kNationSlotCount + i] = kDiplomacyRelationshipPeace;
      relationPropagationMatrix[i * kNationSlotCount + row] = kDiplomacyRelationshipPeace;
      if (g_apTerrainTypeDescriptorTable[row] == 0) {
        relationStandingScores[row * kNationSlotCount + i] = 0x5a;
        relationStandingScores[i * kNationSlotCount + row] = 0x5a;
      }
    }
  }
  // Minor slots 7..22: unconditionally reset both matrices in both directions.
  for (int j = 7; j < kNationSlotCount; ++j) {
    relationPropagationMatrix[row * kNationSlotCount + j] = kDiplomacyRelationshipPeace;
    relationPropagationMatrix[j * kNationSlotCount + row] = kDiplomacyRelationshipPeace;
    relationStandingScores[row * kNationSlotCount + j] = 0x5a;
    relationStandingScores[j * kNationSlotCount + row] = 0x5a;
  }
}

// FUNCTION: IMPERIALISM 0x004eef50
void TDiplomacyMgr::ResetTerrainAdjacencyMatrixRowAndSymmetricLink(NationSlot nationSlot) {
  int row = nationSlot;
  int remaining = kNationSlotCount;
  short* rowCursor = &relationSideEffectMatrix[row * kNationSlotCount];
  short* colCursor = &relationSideEffectMatrix[row];
  do {
    *rowCursor = 0;
    *colCursor = 0;
    ++rowCursor;
    colCursor += kNationSlotCount;
    --remaining;
  } while (remaining != 0);

  TCountry* terrain = g_apTerrainTypeDescriptorTable[row];
  if (terrain == 0) {
    return;
  }
  if (terrain->encodedNationSlot <= 199) {
    return;
  }

  short decodedSlot = terrain->DecodeOwnerNationSlot();
  relationSideEffectMatrix[row * kNationSlotCount + decodedSlot] = 2;

  decodedSlot = terrain->DecodeOwnerNationSlot();
  relationSideEffectMatrix[decodedSlot * kNationSlotCount + row] = 2;
}

// FUNCTION: IMPERIALISM 0x004ef040
void TDiplomacyMgr::Free() {
  if (pendingWarTransitionQueue != 0) {
    pendingWarTransitionQueue->ReleasePtrList();
  }
  pendingWarTransitionQueue = 0;
  delete this;
}

// Restores the diplomacy state from a save. The stream is big-endian, so every short
// block read is followed by an in-place swap pass; the byte blocks
// (pendingPolicyCodeMatrix) and the single short at lastDiplomaticEffortTurn are
// read raw. Field groups added after the initial format are guarded by their
// introducing save version -- an older save simply leaves them at their constructed
// value, which is why the gates must be transcribed exactly even though the current
// format (0x3e) takes every branch.
//
// pendingPolicyTierMatrix, relationMatrixBaselineCopy/798 and
// comparativePowerRows are deliberately absent: they are runtime-derived and
// rebuilt after the load, not persisted.
// FUNCTION: IMPERIALISM 0x004ef080
void TDiplomacyMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);

  stream->ReadBytes(relationStandingScores, sizeof(relationStandingScores));
  SwapShortArrayBytes(relationStandingScores, kNationPairMatrixEntries);

  stream->ReadBytes(relationPropagationMatrix, sizeof(relationPropagationMatrix));
  SwapShortArrayBytes(relationPropagationMatrix, kNationPairMatrixEntries);

  if (g_nSaveFormatVersion > 0x2e) {
    stream->ReadBytes(relationTurnStampMatrix, sizeof(relationTurnStampMatrix));
    SwapShortArrayBytes(relationTurnStampMatrix, kNationPairMatrixEntries);
  }

  stream->ReadBytes(relationCodeMatrix, sizeof(relationCodeMatrix));
  SwapShortArrayBytes(relationCodeMatrix, kDiplomacyPairMatrixEntries);

  stream->ReadBytes(pendingPolicyCodeMatrix, sizeof(pendingPolicyCodeMatrix));
  stream->ReadBytes(&lastDiplomaticEffortTurn, 2);

  if (g_nSaveFormatVersion > 0xb) {
    stream->ReadBytes(relationSideEffectMatrix, sizeof(relationSideEffectMatrix));
    SwapShortArrayBytes(relationSideEffectMatrix, kNationPairMatrixEntries);
  }

  if (g_nSaveFormatVersion > 0xd) {
    // One read per record: 4 bytes for the whole CongressLeadership pair, then 6 for
    // the whole CongressSupportTally. Both are byte-swapped as short arrays.
    stream->ReadBytes(&congressLeadership, sizeof(congressLeadership));
    SwapShortArrayBytes(&congressLeadership, 2);
    stream->ReadBytes(&congressSupport, sizeof(congressSupport));
    SwapShortArrayBytes(&congressSupport, 3);
  }

  if (g_nSaveFormatVersion > 0x1a) {
    stream->ReadBytes(specialRelationSourceSlots, sizeof(specialRelationSourceSlots));
    NationSlot* slot = specialRelationSourceSlots;
    for (int remaining = 0x10; remaining != 0; --remaining) {
      ByteSwapShortInPlace(slot);
      ++slot;
    }
  }

  if (g_nSaveFormatVersion > 0x1b) {
    ReadByteSwappedShortArrayFromStream(stream, specialRelationTargetSlots, 0x10);
  }
}

// Mirror of ReadFrom in the current save format: the writer has no version gates, it
// always emits every field group.
// FUNCTION: IMPERIALISM 0x004ef2a0
void TDiplomacyMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);

  WriteShortArrayElems(stream, relationStandingScores, kNationPairMatrixEntries);
  WriteShortArrayElems(stream, relationPropagationMatrix, kNationPairMatrixEntries);
  WriteShortArrayElems(stream, relationTurnStampMatrix, kNationPairMatrixEntries);
  WriteShortArrayElems(stream, relationCodeMatrix, kDiplomacyPairMatrixEntries);

  stream->WriteBytes(pendingPolicyCodeMatrix, sizeof(pendingPolicyCodeMatrix));
  stream->WriteBytes(&lastDiplomaticEffortTurn, 2);

  WriteShortArrayElems(stream, relationSideEffectMatrix, kNationPairMatrixEntries);
  WriteShortArrayElems(stream, &congressLeadership.chairmanNationSlot, 2);
  WriteShortArrayElems(stream, &congressSupport.chairmanSupportCount, 3);

  NationSlot* slot = specialRelationSourceSlots;
  for (int remaining = 0x10; remaining != 0; --remaining) {
    short value = *slot;
    SwapFirstTwoBytesInBuffer(&value);
    stream->WriteBytes(&value, 2);
    ++slot;
  }

  WriteByteSwappedShortArrayToStream(stream, specialRelationTargetSlots, 0x10);
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
bool TDiplomacyMgr::IsNationPairRelationTurnStampOutOfDate(NationSlot sourceNationSlot,
                                                           NationSlot targetNationSlot) {
  if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) == 0) {
    return false;
  }
  short currentTurn = g_pSimMgr->GetEconomicTurn();
  return relationTurnStampMatrix[sourceNationSlot * kNationSlotCount + targetNationSlot] !=
         currentTurn;
}

// FUNCTION: IMPERIALISM 0x004ef600
bool TDiplomacyMgr::HasAnyWarRelationForNation(NationSlot sourceNationSlot) {
  for (int targetNationSlot = 0; targetNationSlot < 0x17; ++targetNationSlot) {
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004ef650
bool TDiplomacyMgr::HasAnyWarRelationTurnStampOutOfDateForNation(NationSlot sourceNationSlot) {
  for (int targetNationSlot = 0; targetNationSlot < 0x17; ++targetNationSlot) {
    if (IsNationPairRelationTurnStampOutOfDate(sourceNationSlot, targetNationSlot) != 0) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004ef6a0
bool TDiplomacyMgr::IsSpecialRelationSourceForMinorNationSlot(NationSlot nationSlot,
                                                              NationSlot minorNationSlot) {
  return specialRelationSourceSlots[minorNationSlot - 7] == nationSlot;
}

// FUNCTION: IMPERIALISM 0x004ef6d0
bool TDiplomacyMgr::IsSpecialRelationTargetForMinorNationSlot(NationSlot nationSlot,
                                                              NationSlot minorNationSlot) {
  return specialRelationTargetSlots[minorNationSlot - 7] == nationSlot;
}

// FUNCTION: IMPERIALISM 0x004ef700
bool TDiplomacyMgr::ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
    NationSlot sourceNationSlot, NationSlot targetNationSlot, eDipAction action) {
  bool isValid = false;
  if (targetNationSlot == sourceNationSlot) {
    ReadGlobalTDiplomacyTurnStateManager()->proposalArrayMode = 0xe;
    return isValid;
  }

  TCountry* targetTerrain = g_apTerrainTypeDescriptorTable[targetNationSlot];
  short targetTerrainOwner = targetTerrain->encodedNationSlot;
  if (targetTerrainOwner != -1) {
    if (targetTerrainOwner >= 200) {
      proposalArrayMode = 0xc;
      return isValid;
    }
    proposalArrayMode = 0xd;
    return isValid;
  }

  int pairIndex = sourceNationSlot * kNationSlotCount + targetNationSlot;
  switch (action) {
  case kDipActionJoinEmpire:
    if (relationSideEffectMatrix[pairIndex] != 2) {
      proposalArrayMode = 1;
      return isValid;
    }
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode = 2;
      return isValid;
    }
    if (targetNationSlot < 7) {
      proposalArrayMode = 0x12;
      return isValid;
    }
    break;
  case kDipActionAlliance:
    if (targetNationSlot > 6) {
      proposalArrayMode = 3;
      return isValid;
    }
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode = 2;
      return isValid;
    }
    if (GetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot) ==
        kDiplomacyRelationshipAlliance) {
      proposalArrayMode = 0x11;
      return isValid;
    }
    break;
  case kDipActionNonAggressionPact:
    if (relationSideEffectMatrix[pairIndex] != 2) {
      proposalArrayMode = 1;
      return isValid;
    }
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode = 2;
      return isValid;
    }
    if (GetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot) ==
        kDiplomacyRelationshipNonAggressionPact) {
      proposalArrayMode = 0x10;
      return isValid;
    }
    if (targetNationSlot < 7) {
      proposalArrayMode = 0xf;
      return isValid;
    }
    break;
  case kDipActionPeaceTreaty:
    if (IsNationPairRelationTurnStampOutOfDate(sourceNationSlot, targetNationSlot) == 0) {
      proposalArrayMode = 5;
      return isValid;
    }
    break;
  case kDipActionDeclareWar:
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode = 6;
      return isValid;
    }
    break;
  case kDipActionOneTimeGrant:
  case kDipActionRecurringGrant:
    if (relationSideEffectMatrix[pairIndex] < 2) {
      proposalArrayMode = 1;
      return isValid;
    }
    break;
  case kDipActionTradeSubsidy:
  case kDipActionTradePolicy:
    if (relationSideEffectMatrix[pairIndex] == 0) {
      proposalArrayMode = 7;
      return isValid;
    }
    break;
  case kDipActionBoycott:
    if (GetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot) ==
        kDiplomacyRelationshipAlliance) {
      proposalArrayMode = 8;
      return isValid;
    }
    break;
  case kDipActionBuildConsulate:
    if (relationSideEffectMatrix[pairIndex] != 0) {
      proposalArrayMode = 9;
      return isValid;
    }
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode = 2;
      return isValid;
    }
    if (g_apNationStates[sourceNationSlot]->treasuryValue10 < 500) {
      proposalArrayMode = 0x16;
      return isValid;
    }
    break;
  case kDipActionBuildEmbassy:
    if (relationSideEffectMatrix[pairIndex] == 0) {
      proposalArrayMode = 0xa;
      return isValid;
    }
    if (relationSideEffectMatrix[pairIndex] == 2) {
      proposalArrayMode = 0xb;
      return isValid;
    }
    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode = 2;
      return isValid;
    }
    if (g_apNationStates[sourceNationSlot]->treasuryValue10 < 5000) {
      proposalArrayMode = 0x15;
      return isValid;
    }
    break;
  }
  isValid = true;
  return isValid;
}

// FUNCTION: IMPERIALISM 0x004efc30
bool TDiplomacyMgr::HasAllianceGuardForNationPair(NationSlot nationSlot,
                                                  NationSlot guardedNationSlot) {
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
void TDiplomacyMgr::SetRelationship(NationSlot sourceNationSlot, NationSlot targetNationSlot,
                                    short standingScore) {
  int source = sourceNationSlot;
  int target = targetNationSlot;
  int forwardIndex = source * kNationSlotCount + target;
  short* forwardScore = &relationStandingScores[forwardIndex];
  short requestedScore = standingScore;
  if (requestedScore == *forwardScore) {
    return;
  }

  int clampedScore = requestedScore;
  if (requestedScore < 0) {
    clampedScore = 0;
  }
  if (requestedScore > 0xff && sourceNationSlot != targetNationSlot) {
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
  relationStandingScores[reverseIndex] = static_cast<short>(clampedScore);

  if (IsGreatPower(sourceNationSlot) != 0) {
    int minorNationSlot = 7;
    TCountry** terrainCursor = &g_apTerrainTypeDescriptorTable[7];
    do {
      TMinor* terrain = static_cast<TMinor*>(*terrainCursor);
      if (terrain != 0 && terrain->IsColonyOf(sourceNationSlot) != 0) {
        SetRelationshipsToMatch(minorNationSlot, sourceNationSlot);
      }
      terrainCursor++;
      minorNationSlot++;
    } while (terrainCursor < &g_apTerrainTypeDescriptorTable[23]);
  }

  if (IsGreatPower(targetNationSlot) != 0) {
    int minorNationSlot = 7;
    TCountry** terrainCursor = &g_apTerrainTypeDescriptorTable[7];
    do {
      TMinor* terrain = static_cast<TMinor*>(*terrainCursor);
      if (terrain != 0 && terrain->IsColonyOf(targetNationSlot) != 0) {
        SetRelationshipsToMatch(minorNationSlot, targetNationSlot);
      }
      terrainCursor++;
      minorNationSlot++;
    } while (terrainCursor < &g_apTerrainTypeDescriptorTable[23]);
  }
}

// FUNCTION: IMPERIALISM 0x004efe30
void TDiplomacyMgr::SetRelationshipsToMatch(NationSlot destinationNationSlot,
                                            NationSlot sourceNationSlot) {
  short* destinationColumnCursor = &relationStandingScores[destinationNationSlot];
  short* destinationRowCursor = &relationStandingScores[destinationNationSlot * kNationSlotCount];
  short* sourceRowCursor = &relationStandingScores[sourceNationSlot * kNationSlotCount];
  short* sourceColumnCursor = &relationStandingScores[sourceNationSlot];

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
void TDiplomacyMgr::ApplyPeaceRelationshipAndQueueEvent18ForTargetNation(
    NationSlot sourceNationSlot, NationSlot targetNationSlot, unsigned char updateMode) {
  SetNationPairDiplomacyRelationCodeFinal(sourceNationSlot, targetNationSlot,
                                          kDiplomacyRelationshipPeace);
  if (updateMode == 1) {
    InflictWarPenalty(sourceNationSlot, targetNationSlot, 0);
  }

  TMinor* targetTerrain = static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[targetNationSlot]);
  if (targetTerrain != 0) {
    targetTerrain->AddNoticeFrom(sourceNationSlot, 0x139);
    g_pNewsMgr->AddTreatyEvent(kInterNationEventPeaceRelationshipPropagated, targetNationSlot,
                               sourceNationSlot, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004eff40
void TDiplomacyMgr::InflictWarPenalty(NationSlot sourceNationSlot, NationSlot targetNationSlot,
                                      unsigned char updateMode) {
  int source = sourceNationSlot;
  int target = targetNationSlot;
  short sourceTargetStanding = relationStandingScores[source * kNationSlotCount + target];

  if (updateMode == 1) {
    if (sourceTargetStanding - 0x32 < 0x31) {
      SetRelationship(sourceNationSlot, targetNationSlot, sourceTargetStanding - 0x32);
    } else {
      SetRelationship(sourceNationSlot, targetNationSlot, 0x31);
    }
  } else {
    int adjustment = ((0x5a - sourceTargetStanding) * sourceTargetStanding) / 200;
    if (static_cast<short>(adjustment) < 0) {
      SetRelationship(sourceNationSlot, targetNationSlot, sourceTargetStanding + adjustment);
    }
  }

  int candidateNationSlot = 0;
  TCountry** terrainCursor = g_apTerrainTypeDescriptorTable;
  do {
    TMinor* candidateTerrain = static_cast<TMinor*>(*terrainCursor);
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(candidateNationSlot) != 0 &&
        candidateNationSlot != sourceNationSlot && candidateNationSlot != targetNationSlot &&
        candidateTerrain->encodedNationSlot == -1) {
      int divisorTier;
      if (IsGreatPower(targetNationSlot) == 0) {
        if (IsGreatPower(candidateNationSlot) == 0) {
          divisorTier = candidateTerrain->IsInConsortiumWith(sourceNationSlot) != 0 ? 2 : 4;
        } else {
          divisorTier = 8;
        }
      } else {
        divisorTier = IsGreatPower(candidateNationSlot) != 0 ? 4 : 8;
      }

      short currentStanding =
          relationStandingScores[source * kNationSlotCount + candidateNationSlot];
      short targetCandidateStanding =
          relationStandingScores[target * kNationSlotCount + candidateNationSlot];
      int candidateAdjustment =
          ((0x5a - targetCandidateStanding) * sourceTargetStanding) / (divisorTier * 0x32);
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
      SetRelationship(sourceNationSlot, candidateNationSlot, currentStanding + appliedDelta);
    }

    candidateNationSlot++;
    terrainCursor++;
  } while (static_cast<short>(candidateNationSlot) <= 0x16);
}

// FUNCTION: IMPERIALISM 0x004f01e0
void TDiplomacyMgr::ApplyDiplomacyInterNationStatesForTurn() {
  // Pre-pass (unless localization phase 2): run the per-nation begin-turn slot 0x1c8
  // over the seven majors descending, gated on the nation's eligibility byte at +0xa0.
  if (g_pSimMgr->multiplayerSessionRole != 2) {
    TGreatPower** nationCursor = &g_apNationStates[6];
    int remaining = 7;
    do {
      TGreatPower* nation = *nationCursor;
      if (nation != 0 && nation->diplomacyEligibilityA0 == 0) {
        nation->SetDiplomacyPolicies();
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

  if (g_pSimMgr->multiplayerSessionRole == 2) {
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
        (*nationCursor)->FinishDiplomacyPhase();
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
        do {
          if (g_apTerrainTypeDescriptorTable[col] != 0) {
            TGreatPower* rowNation = g_apNationStates[row];
            short flag = rowNation->diplomacyGrantByNation[col];
            if (flag != -1) {
              if (IsGreatPower(col) != 0) {
                // arg0 is the constant 0 (held in [esp+0x10] across the loop in the original).
                g_apNationStates[col]->AddNoticeFrom(0, flag);
              }
              rowNation->GiveGrantTo(col);
            }
            short relationCode = rowNation->diplomacyPolicyByNation[col];
            if (relationCode != -1) {
              if (relationCode == 0x133) {
                relationSideEffectMatrix[rowBase + col] = 1;
                relationSideEffectMatrix[row + colBase] = 1;
                g_pNewsMgr->AddTreatyEvent(kInterNationEventTradeConsulateEstablished, row, col, 0);
              } else if (relationCode == 0x134) {
                relationSideEffectMatrix[rowBase + col] = 2;
                relationSideEffectMatrix[row + colBase] = 2;
                g_pNewsMgr->AddTreatyEvent(kInterNationEventEmbassyEstablished, row, col, 0);
              } else if (relationCode == kDiplomacyProposalDeclareWar) {
                if (IsNationPairAtWar(row, col) == 0) {
                  g_apNationStates[row]->QueueWarTransitionAndNotifyThirdPartyIfNeeded(col, 4, -1);
                }
              } else {
                g_apTerrainTypeDescriptorTable[col]->AddOfferFrom(
                    static_cast<NationSlot>(row),
                    static_cast<DiplomacyProposalCodeStorage>(relationCode));
              }
            }
          }
          ++col;
          colBase += kNationSlotCount;
        } while (static_cast<short>(col) < kNationSlotCount);
      }
      ++row;
      rowBase += kNationSlotCount;
    } while (static_cast<short>(row) < 7);
  }
}

// FUNCTION: IMPERIALISM 0x004f0590
void TDiplomacyMgr::SetLastDiploEffort() {
  lastDiplomaticEffortTurn = g_pSimMgr->GetEconomicTurn();
}

// FUNCTION: IMPERIALISM 0x004f05c0
void TDiplomacyMgr::SelectPriorityNationIndicesForMinorCapabilityRows() {
  // Ground truth walks the table by pointer with a separate count-down counter
  // (`dec edi; jne` at 0x4f05f4), not an ascending index compare.
  TGreatPower** nationSlot = g_apNationStates;
  for (int remaining = 7; remaining != 0; --remaining, ++nationSlot) {
    if (*nationSlot != NULL) {
      (*nationSlot)->InitializeDiplomacyOffers();
    }
  }

  // The original dereferences g_pSimMgr unguarded and materializes the mode test
  // into a byte before branching (`cmp [edx+0x44],2; sete cl; test cl,cl; je`),
  // so the null check here was ours, not the retail code's.
  unsigned char isClientSession = g_pSimMgr->multiplayerSessionRole == 2;
  if (isClientSession) {
    pendingWarTransitionQueue->InvokePtrListResetHook();
    return;
  }

  // Ground truth sets both tie flags to 1 once in the prologue (0x4f05d2/0x4f05d7,
  // the [esp+0x13]/[esp+0x12] bytes) rather than re-initializing them per minor
  // slot, so they live at function scope here.
  bool isOfferTie = true;
  bool isRelationTie = true;

  for (int minorSlot = 7; minorSlot < 23; minorSlot++) {
    TCountry* minorDescriptor = g_apTerrainTypeDescriptorTable[minorSlot];
    short bestOfferScore = 0x8b;
    int bestOfferNation = -1;

    int bestRelationScore = 9000;
    int bestRelationNation = -1;
    (void)isOfferTie;
    (void)isRelationTie;

    unsigned int randSeed1 = 0;
    unsigned int randSeed2 = 0;

    for (int gpSlot = 0; gpSlot < 7; gpSlot++) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<NationSlot>(gpSlot))) {
        int standingIndex = minorSlot * kNationSlotCount + gpSlot;
        int sideEffectIndex = gpSlot * kNationSlotCount + minorSlot;
        if (relationSideEffectMatrix[sideEffectIndex] != 0) {
          short relationVal = relationStandingScores[standingIndex];
          if (bestOfferScore < relationVal) {
            isOfferTie = false;
            bestOfferNation = gpSlot;
            bestOfferScore = relationVal;
          } else if (relationVal == bestOfferScore) {
            isOfferTie = true;
            if (minorDescriptor->IsColonyOf(gpSlot)) {
              bestOfferNation = gpSlot;
              bestOfferScore = relationVal;
            } else {
              unsigned int rnd = (unsigned int)relationVal + 0x31 +
                                 (unsigned int)g_pSimMgr->GetEconomicTurn() + gpSlot;
              if (rnd == 0)
                rnd = randSeed1;
              randSeed1 = rnd * 0x15a4e35 + 1;
              if ((randSeed1 >> 12) & 1) {
                bestOfferNation = gpSlot;
                bestOfferScore = relationVal;
              }
            }
          }
        }

        int score = 0;
        if (relationSideEffectMatrix[sideEffectIndex] >= 1) {
          score = (200 - relationSideEffectMatrix[sideEffectIndex]) *
                  relationStandingScores[standingIndex];
        }
        if (bestRelationScore < score) {
          isRelationTie = false;
          bestRelationNation = gpSlot;
          bestRelationScore = score;
        } else if (score == bestRelationScore) {
          isRelationTie = true;
          if (minorDescriptor->IsColonyOf(gpSlot)) {
            bestRelationNation = gpSlot;
            bestRelationScore = score;
          } else {
            short relationVal = relationStandingScores[standingIndex];
            unsigned int rnd = (unsigned int)relationVal + 0x31 +
                               (unsigned int)g_pSimMgr->GetEconomicTurn() + gpSlot;
            if (rnd == 0)
              rnd = randSeed2;
            randSeed2 = rnd * 0x15a4e35 + 1;
            if ((randSeed2 >> 12) & 1) {
              bestRelationNation = gpSlot;
              bestRelationScore = score;
            }
          }
        }
      }
    }

    if (bestOfferNation != -1) {
      int priorOfferNation = specialRelationSourceSlots[minorSlot - 7];
      if (!isOfferTie && priorOfferNation != bestOfferNation && priorOfferNation != -1 &&
          relationSideEffectMatrix[priorOfferNation * kNationSlotCount + minorSlot] >= 1 &&
          g_pSimMgr->IsNationSlotEligibleForEventProcessing(priorOfferNation) != 0) {
        g_apTerrainTypeDescriptorTable[priorOfferNation]->AddNoticeFrom(minorSlot, 0x13a);
      }
      specialRelationSourceSlots[minorSlot - 7] = static_cast<NationSlot>(bestOfferNation);
    }
    if (bestRelationNation != -1) {
      int priorRelationNation = specialRelationTargetSlots[minorSlot - 7];
      if (!isRelationTie && priorRelationNation != bestRelationNation &&
          priorRelationNation != -1 &&
          g_pSimMgr->IsNationSlotEligibleForEventProcessing(priorRelationNation) != 0 &&
          relationSideEffectMatrix[priorRelationNation * kNationSlotCount + minorSlot] >= 1 &&
          g_apTerrainTypeDescriptorTable[priorRelationNation] != 0) {
        g_apTerrainTypeDescriptorTable[priorRelationNation]->AddNoticeFrom(minorSlot, 0x13b);
      }
      specialRelationTargetSlots[minorSlot - 7] = static_cast<NationSlot>(bestRelationNation);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004f09c0
void TDiplomacyMgr::QueueNationPairWarTransition(NationSlot sourceNationSlot,
                                                 NationSlot targetNationSlot) {
  WarTransitionPair pair;
  pair.sourceNationSlot = sourceNationSlot;
  pair.targetNationSlot = targetNationSlot;
  pendingWarTransitionQueue->InsertCopiedRecordAtFrontOfPtrList(&pair);
  SetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot, kDiplomacyRelationshipWar,
                                     1);
}

// FUNCTION: IMPERIALISM 0x004f0a10
void TDiplomacyMgr::ProcessQueuedWarTransitions() {
  if (pendingWarTransitionQueue->GetSize() != 0) {
    char propagatedTransition = 0;
    WarTransitionPair* pair =
        static_cast<WarTransitionPair*>(pendingWarTransitionQueue->PeekFirstPtrListEntry());
    int targetNationSlot = pair->targetNationSlot;
    int sourceNationSlot = pair->sourceNationSlot;
    pendingWarTransitionQueue->RemovePtrListEntryByOneBasedIndexAndFree(1);

    if (IsNationPairAtWar(sourceNationSlot, targetNationSlot) == 0) {
      SetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot,
                                         kDiplomacyRelationshipWar, 0);
    }

    static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[targetNationSlot])
        ->AddNoticeFrom(sourceNationSlot, kDiplomacyProposalDeclareWar);

    g_pNewsMgr->AddTreatyEvent(kInterNationEventWarDeclaredAgainstSubject, targetNationSlot,
                               sourceNationSlot, 0);
    g_pNewsMgr->AddTreatyEvent(kInterNationEventWarDeclaredBySubject, sourceNationSlot,
                               targetNationSlot, 0);

    if (targetNationSlot < 7) {
      g_apNationStates[sourceNationSlot]->AddNoticeFrom(targetNationSlot, 0xc8);
    }

    if (IsGreatPower(targetNationSlot) == 0) {
      int ownerNationSlot = -1;
      TCountry* targetTerrain = g_apTerrainTypeDescriptorTable[targetNationSlot];
      bool isUnowned = (targetTerrain->encodedNationSlot == static_cast<short>(ownerNationSlot));
      if (isUnowned) {
        ownerNationSlot = GetFavorite(targetNationSlot, 1, 2);
      }

      if (ownerNationSlot > -1) {
        int transitionResult = g_apNationStates[ownerNationSlot]->HandleWarTransitionRequest(
            targetNationSlot, sourceNationSlot);
        propagatedTransition = (transitionResult == 2);
      }
    } else {
      int otherNationSlot;
      for (otherNationSlot = 0; otherNationSlot < 7; ++otherNationSlot) {
        if (relationPropagationMatrix[targetNationSlot * kNationSlotCount + otherNationSlot] ==
                kDiplomacyRelationshipAlliance &&
            IsNationPairAtWar(otherNationSlot, sourceNationSlot) == 0) {
          int transitionResult =
              g_apNationStates[otherNationSlot]->HandleWarTransitionRequestWithRoleSwap(
                  targetNationSlot, sourceNationSlot, 0);
          propagatedTransition = (transitionResult == 2);
        }
      }

      for (otherNationSlot = 0; otherNationSlot < 7; ++otherNationSlot) {
        if (relationPropagationMatrix[sourceNationSlot * kNationSlotCount + otherNationSlot] ==
                kDiplomacyRelationshipAlliance &&
            ReadGlobalTDiplomacyTurnStateManager()->IsNationPairAtWar(otherNationSlot,
                                                                      targetNationSlot) == 0) {
          int transitionResult =
              g_apNationStates[otherNationSlot]->HandleWarTransitionRequestWithRoleSwap(
                  targetNationSlot, sourceNationSlot, 1);
          propagatedTransition = (transitionResult == 2);
        }
      }
    }

    if (propagatedTransition == 0) {
      TNextTradeCommand* packet = new TNextTradeCommand();
      InitializeNextTradeCommandForHandler(packet, kTurnEventTagNext, g_pAmbitApplication);
      g_pAmbitApplication->DispatchUiSelectionToHandler(packet);
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
  // Ground truth zeroes a register once (xor ebp,ebp at 0x4f0e33) and spends it on
  // both the matrix probe (cmp word ptr [edi], bp) and four dword locals it clears
  // up front (mov [esp+0x28]/[esp+0x2c]/[esp+0x34]/[esp+0x3c], ebp at 0x4f0e40), so
  // these are function-scope zero-initialized rather than declared at first use.
  int topNationSlot = 0;
  int secondNationSlot = 0;
  int topPower = 0;
  int secondPower = 0;

  bool forceFullClear = (forceOrMode == 2);
  if (relationCodeMatrix[0] == 0) {
    InitializeDiplomacyStandingBaselineRandom();
  }
  if (forceFullClear) {
    memset(relationCodeMatrix, 0, sizeof(relationCodeMatrix));
  }

  BuildMajorNationDiplomacyStandingRanking(&topNationSlot, &secondNationSlot);
  congressLeadership.counterpartNationSlot = static_cast<short>(secondNationSlot);
  congressLeadership.chairmanNationSlot = static_cast<short>(topNationSlot);
  topPower = comparativePowerRows[topNationSlot][1];
  secondPower = comparativePowerRows[secondNationSlot][1];

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
          (relationStandingScores[topNationSlot * kNationSlotCount + nationSlot] * 100 / 255 +
           topPower) /
          2;
      secondSideScore[nationSlot] =
          (relationStandingScores[secondNationSlot * kNationSlotCount + nationSlot] * 100 / 255 +
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
    pendingPolicyTierMatrix[tileIndex] = -1;
    Province* cityRecord = &g_pGlobalMapState->cityScoreTable[tileIndex];
    int ownerNationCode = cityRecord->ownerNationCode00;
    if (ownerNationCode == -1) {
      continue;
    }

    int topScore;
    int secondScore;
    if (cityRecord->formerOwnerNationCode01 < 7) {
      topScore =
          (comparativePowerRows[topNationSlot][0] + comparativePowerRows[topNationSlot][3]) / 2;
      secondScore =
          (comparativePowerRows[secondNationSlot][0] + comparativePowerRows[secondNationSlot][3]) /
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
    pendingPolicyCodeMatrix[tileIndex] = -1;
    bool topSideWins = (ownerNationCode == topNationSlot) ||
                       g_apTerrainTypeDescriptorTable[ownerNationCode]->IsColonyOf(topNationSlot);
    bool secondSideWins =
        !topSideWins &&
        ((ownerNationCode == secondNationSlot) ||
         g_apTerrainTypeDescriptorTable[ownerNationCode]->IsColonyOf(secondNationSlot));
    if (topSideWins) {
      ++topSideCount;
      pendingPolicyCodeMatrix[tileIndex] = static_cast<signed char>(topNationSlot);
      pendingPolicyTierMatrix[tileIndex] = 0;
    } else if (secondSideWins) {
      ++secondSideCount;
      pendingPolicyCodeMatrix[tileIndex] = static_cast<signed char>(secondNationSlot);
      pendingPolicyTierMatrix[tileIndex] = 0;
    } else {
      short threshold = relationCodeMatrix[tileIndex];
      short delta;
      if (topScore < secondScore) {
        if (threshold <= secondScore - topScore) {
          ++secondSideCount;
          pendingPolicyCodeMatrix[tileIndex] = static_cast<signed char>(secondNationSlot);
          delta = static_cast<short>((secondScore - topScore) - threshold);
          pendingPolicyTierMatrix[tileIndex] = delta;
          if (maxResidual < delta) {
            maxResidual = delta;
          }
        }
      } else if (topScore - secondScore >= threshold) {
        ++topSideCount;
        pendingPolicyCodeMatrix[tileIndex] = static_cast<signed char>(topNationSlot);
        delta = static_cast<short>((topScore - secondScore) - threshold);
        pendingPolicyTierMatrix[tileIndex] = delta;
        if (maxResidual < delta) {
          maxResidual = delta;
        }
      }
    }
  }

  for (int fillIndex = 0; fillIndex < kDiplomacyPairMatrixEntries; ++fillIndex) {
    short value = pendingPolicyTierMatrix[fillIndex];
    if (value == 0) {
      pendingPolicyTierMatrix[fillIndex] = static_cast<short>(rand() % 15 + 1);
    } else if (value > 0) {
      pendingPolicyTierMatrix[fillIndex] = static_cast<short>(maxResidual - value + 15);
    }
  }

  int neutralCount = totalOwnedCount - topSideCount - secondSideCount;
  congressSupport.chairmanSupportCount = static_cast<short>(topSideCount);
  congressSupport.counterpartSupportCount = static_cast<short>(secondSideCount);
  congressSupport.neutralCount = static_cast<short>(neutralCount);

  int winnerNationSlot = -1;
  if (secondSideCount < topSideCount) {
    if (forceFullClear || topSideCount >= totalOwnedCount * 2 / 3) {
      winnerNationSlot = topNationSlot;
    } else if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(
                   static_cast<short>(topNationSlot)) &&
               g_apNationStates[topNationSlot]->pendingActionStatus.roles.actionStatus0B < '3') {
      g_apNationStates[topNationSlot]->SetNationPendingActionStateAndPayload(0xb, -1);
    }
  } else if (topSideCount < secondSideCount) {
    if (forceFullClear || secondSideCount >= totalOwnedCount * 2 / 3) {
      winnerNationSlot = secondNationSlot;
    } else if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(
                   static_cast<short>(secondNationSlot)) &&
               g_apNationStates[secondNationSlot]->pendingActionStatus.roles.actionStatus0B < '3') {
      g_apNationStates[secondNationSlot]->SetNationPendingActionStateAndPayload(0xb, -1);
    }
  } else if (forceFullClear) {
    winnerNationSlot = topNationSlot;
  }

  if (winnerNationSlot != -1) {
    lastProcessedNationSlot = static_cast<short>(winnerNationSlot);
  }
  if (g_pSimMgr->multiplayerSessionRole == 1) {
    g_pGameFlowState->EmitTurnEvent26DiplomacyMatrixSnapshot();
  }
}

// Seeds relationCodeMatrix with a per-city baseline value (indexed parallel to
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
    relationCodeMatrix[cityIndex] = baseline;
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
        sum += comparativePowerRows[nationSlot][metric];
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
    comparativePowerRows[i][0] = army;
    if (army > maxArmy) {
      maxArmy = army;
    }
    int relation = g_apNationStates[i]->RecomputeNationComparativePowerMetrics_Impl();
    comparativePowerRows[i][1] = relation;
    if (relation > maxRelation) {
      maxRelation = relation;
    }
    int commodity = g_apNationStates[i]->SumCommodityRecordAccumulatedValues();
    comparativePowerRows[i][3] = commodity;
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
      comparativePowerRows[i][0] = comparativePowerRows[i][0] * 100 / maxArmy;
      comparativePowerRows[i][1] = comparativePowerRows[i][1] * 100 / maxRelation;
      comparativePowerRows[i][3] = comparativePowerRows[i][3] * 100 / maxCommodity;
      int territory = territoryScore[i] * 50 / maxTerritory;
      territoryScore[i] = territory;
      int tech = techScore[i] * 50 / maxTech;
      techScore[i] = tech;
      comparativePowerRows[i][2] = territory + tech;
    } else {
      comparativePowerRows[i][0] = 0;
      comparativePowerRows[i][1] = 0;
      comparativePowerRows[i][2] = 0;
      comparativePowerRows[i][3] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004f1970
bool TDiplomacyMgr::HasNationPairNeedLevel300(NationSlot sourceNation, NationSlot targetNation) {
  int source = sourceNation;
  int target = targetNation;
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
  short standingScore = relationStandingScores[source * kNationSlotCount + target];
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
      relationPropagationMatrix[sourceNationSlot * kNationSlotCount + targetNationSlot]);
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
  return (&relationPropagationMatrix[sourceNationSlot * kNationSlotCount])[targetNationSlot];
}

// FUNCTION: IMPERIALISM 0x004f1b40
void TDiplomacyMgr::SetNationPairDiplomacyRelationCodeFinal(
    NationSlot sourceNationSlot, NationSlot targetNationSlot,
    DiplomacyRelationshipStorage relationship) {
  SetNationPairDiplomacyRelationCode(sourceNationSlot, targetNationSlot, relationship, 1);
}

// FUNCTION: IMPERIALISM 0x004f1b70
void TDiplomacyMgr::SetNationPairDiplomacyRelationCode(NationSlot sourceNationSlot,
                                                       NationSlot targetNationSlot,
                                                       DiplomacyRelationshipStorage relationship,
                                                       unsigned char updateMode) {
  int source = sourceNationSlot;
  int target = targetNationSlot;
  int forwardIndex = source * kNationSlotCount + target;
  DiplomacyRelationshipStorage newRelationship = relationship;
  if (newRelationship == relationPropagationMatrix[forwardIndex]) {
    return;
  }

  relationPropagationMatrix[forwardIndex] = newRelationship;
  int reverseIndex = target * kNationSlotCount + source;
  relationPropagationMatrix[reverseIndex] = newRelationship;
  relationTurnStampMatrix[forwardIndex] = g_pSimMgr->GetEconomicTurn();
  relationTurnStampMatrix[reverseIndex] = g_pSimMgr->GetEconomicTurn();

  if (IsGreatPower(sourceNationSlot) != 0) {
    g_apNationStates[source]->DispatchNationDiplomacySlotActionByMode(
        target, static_cast<DiplomacyRelationship>(relationship));
  }
  if (IsGreatPower(targetNationSlot) != 0) {
    g_apNationStates[target]->DispatchNationDiplomacySlotActionByMode(
        source, static_cast<DiplomacyRelationship>(relationship));
  }

  switch (newRelationship) {
  case 0:
  case 1:
    break;
  case kDiplomacyRelationshipAlliance:
    g_pNewsMgr->AddTreatyEvent(kInterNationEventAllianceRelationshipEstablished, source, target, 0);
    return;
  case kDiplomacyRelationshipNonAggressionPact:
    SetRelationship(sourceNationSlot, targetNationSlot, relationStandingScores[forwardIndex] + 10);
    break;
  case kDiplomacyRelationshipPeace:
    if (relationStandingScores[forwardIndex] <= 0x31) {
      SetRelationship(sourceNationSlot, targetNationSlot, 0x32);
    }
    if (IsGreatPower(sourceNationSlot) != 0) {
      g_apNationStates[source]->StopBeingEnemiesWith(target);
    }
    if (IsGreatPower(targetNationSlot) != 0) {
      g_apNationStates[target]->StopBeingEnemiesWith(source);
    }
    if ((IsGreatPower(sourceNationSlot) != 0) && (IsGreatPower(targetNationSlot) != 0)) {
      relationSideEffectMatrix[forwardIndex] = 2;
      relationSideEffectMatrix[reverseIndex] = 2;
      g_apTerrainTypeDescriptorTable[source]->SetTradePolicyTo(
          static_cast<NationSlot>(targetNationSlot), 100);
      g_apTerrainTypeDescriptorTable[target]->SetTradePolicyTo(
          static_cast<NationSlot>(sourceNationSlot), 100);
      return;
    }
    break;
  case kDiplomacyRelationshipJoinedEmpire:
    SetRelationship(sourceNationSlot, targetNationSlot, 0xff);
    break;
  case kDiplomacyRelationshipWar: {
    TCountry* sourceTerrain = g_apTerrainTypeDescriptorTable[source];
    TCountry* targetTerrain = g_apTerrainTypeDescriptorTable[target];
    if ((sourceTerrain->encodedNationSlot == -1) && (targetTerrain->encodedNationSlot < 200)) {
      g_pNewsMgr->AddTreatyEvent(kInterNationEventWarWithIndependentMinor, source, target, 0);
    }
    sourceTerrain->SetTradePolicyTo(static_cast<NationSlot>(targetNationSlot), 300);
    targetTerrain->SetTradePolicyTo(static_cast<NationSlot>(sourceNationSlot), 300);
    relationSideEffectMatrix[forwardIndex] = 0;
    relationSideEffectMatrix[reverseIndex] = 0;
    if (IsGreatPower(sourceNationSlot) != 0) {
      g_apNationStates[source]->PruneInvalidTrackedEntriesAndNotifyOwner();
    }
    if (IsGreatPower(targetNationSlot) != 0) {
      g_apNationStates[target]->PruneInvalidTrackedEntriesAndNotifyOwner();
    }
    if (static_cast<char>(updateMode) == 1) {
      InflictWarPenalty(sourceNationSlot, targetNationSlot, 1);
      return;
    }
  } break;
  }
}

// FUNCTION: IMPERIALISM 0x004f1f20
short TDiplomacyMgr::LookupOrderCompatibilityMatrixValue(int sourceNationSlot,
                                                         int targetNationSlot) {
  short* row = &relationSideEffectMatrix[sourceNationSlot * kNationSlotCount];
  return row[targetNationSlot];
}

// FUNCTION: IMPERIALISM 0x004f1f50
bool TDiplomacyMgr::IsGreatPower(NationSlot nationSlot) {
  return nationSlot < 7;
}

// FUNCTION: IMPERIALISM 0x004f1f70
void TDiplomacyMgr::BuildRelationshipList(NationSlot sourceNationSlot, short primaryOnlyFlag,
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
        entry.standingScore = relationStandingScores[source * kNationSlotCount + candidateIndex];
        list->InsertCopiedRecordSortedByComparator(&entry);
      }
    }
    candidateNationSlot++;
    candidateIndex++;
    terrainCursor++;
  } while (candidateNationSlot <= lastNationSlot);
}

// FUNCTION: IMPERIALISM 0x004f2050
int TDiplomacyMgr::GetNumAllies(int sourceNationSlot) {
  int allianceCount = 0;
  DiplomacyRelationshipStorage* relationCursor =
      &relationPropagationMatrix[sourceNationSlot * kNationSlotCount];
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
int TDiplomacyMgr::GetAllyNumber(int nthAllianceIndex, int sourceNationSlot) {
  int allianceOrdinal = 0;
  int candidateNationSlot = 0;
  do {
    if (allianceOrdinal == nthAllianceIndex + 1) {
      return candidateNationSlot - 1;
    }
    if (relationPropagationMatrix[sourceNationSlot * kNationSlotCount + candidateNationSlot] ==
        kDiplomacyRelationshipAlliance) {
      allianceOrdinal++;
    }
    candidateNationSlot++;
  } while (candidateNationSlot < 7);
  return candidateNationSlot - 1;
}

// FUNCTION: IMPERIALISM 0x004f2100
int TDiplomacyMgr::GetFavorite(int sourceNationSlot, int primaryOnlyFlag) {
  TSortedByRelationshipList* list = new TSortedByRelationshipList();
  list->recordSize14 = 4;
  BuildRelationshipList(sourceNationSlot, static_cast<char>(primaryOnlyFlag), list);
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
int TDiplomacyMgr::GetFavorite(int sourceNationSlot, int primaryOnlyFlag, int sideEffectCode) {
  if (static_cast<short>(sideEffectCode) == 0) {
    return GetFavorite(sourceNationSlot, primaryOnlyFlag);
  }

  TSortedByRelationshipList* list = new TSortedByRelationshipList();
  list->recordSize14 = 4;
  BuildRelationshipList(sourceNationSlot, static_cast<char>(primaryOnlyFlag), list);
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
    if (relationSideEffectMatrix[source * kNationSlotCount + candidateNationSlot] ==
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
void TDiplomacyMgr::RebuildMinorNationDispositionLookupTables(NationSlot nationCode) {
  // Ground truth walks the aux-slot table by byte offset (esi stepping 4 into
  // [esi + &g_apSecondaryNationStateSlots[7]]) rather than re-scaling an index,
  // and carries the minor slot as its own counter seeded to 7 (mov [esp+0x14], 7
  // at 0x4f24a9) instead of recomputing 7 + auxIndex in the body.
  TMinor** auxSlot = g_apNationAuxRuntimeStateSlots;
  short minorSlot = 7;
  for (int auxIndex = 0; auxIndex < 16; ++auxIndex, ++auxSlot, ++minorSlot) {
    TMinor* candidate = *auxSlot;
    if (!candidate->IsColonyOf(nationCode)) {
      continue;
    }
    candidate->RegainIndependence();

    TCountry* capabilityObject = g_apTerrainTypeDescriptorTable[7 + auxIndex];

    for (int majorSlot = 0; majorSlot < 7; ++majorSlot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(majorSlot)) {
        relationStandingScores[majorSlot * kNationSlotCount + minorSlot] = 0x5a;
        relationStandingScores[minorSlot * kNationSlotCount + majorSlot] = 0x5a;
        relationPropagationMatrix[majorSlot * kNationSlotCount + minorSlot] =
            kDiplomacyRelationshipPeace;
        relationPropagationMatrix[minorSlot * kNationSlotCount + majorSlot] =
            kDiplomacyRelationshipPeace;
      }
    }

    for (int otherMinorSlot = 7; otherMinorSlot < kNationSlotCount; ++otherMinorSlot) {
      short standingValue;
      DiplomacyRelationshipStorage propagationValue;
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(otherMinorSlot)) {
        TCountry* otherMinorCandidate = g_apTerrainTypeDescriptorTable[otherMinorSlot];
        if (otherMinorCandidate->encodedNationSlot >= 200) {
          short normalizedSlot = capabilityObject->DecodeOwnerNationSlot();
          int lookupIndex = normalizedSlot * kNationSlotCount + minorSlot;
          standingValue = relationStandingScores[lookupIndex];
          propagationValue = relationPropagationMatrix[lookupIndex];
        } else if (capabilityObject->IsInConsortiumWith(static_cast<short>(otherMinorSlot))) {
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
      relationStandingScores[otherMinorSlot * kNationSlotCount + minorSlot] = standingValue;
      relationStandingScores[minorSlot * kNationSlotCount + otherMinorSlot] = standingValue;
      relationPropagationMatrix[otherMinorSlot * kNationSlotCount + minorSlot] = propagationValue;
      relationPropagationMatrix[minorSlot * kNationSlotCount + otherMinorSlot] = propagationValue;
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
      0x89c, relationStandingScores, relationMatrixBaselineCopy);
  packet->flag20 = 0;
  if (relationMatrixBaselineCopy == 0) {
    relationMatrixBaselineSize = 0x1138;
    relationMatrixBaselineCopy = new short[0x89c];
  }
  memcpy(relationMatrixBaselineCopy, relationStandingScores, relationMatrixBaselineSize);
  return packet;
}

// FUNCTION: IMPERIALISM 0x004f27f0
void TDiplomacyMgr::ApplyTurnEvent2SyncPacketToRelationMatrix(TurnEvent2SyncPacket* packet) {
  packet->ApplyEncodedDeltaPayloadToBufferByMode(relationStandingScores);
}

// FUNCTION: IMPERIALISM 0x004f2820
char TDiplomacyMgr::BuildEmbassy(DiplomaticMissionLevelStorage missionLevel, int sourceNation,
                                 int targetNation) {
  relationSideEffectMatrix[sourceNation * kNationSlotCount + targetNation] = missionLevel;
  relationSideEffectMatrix[targetNation * kNationSlotCount + sourceNation] = missionLevel;
  InterNationEventKind eventKind = missionLevel == kDiplomaticMissionEmbassy
                                       ? kInterNationEventEmbassyEstablished
                                       : kInterNationEventTradeConsulateEstablished;
  g_pNewsMgr->AddTreatyEvent(eventKind, sourceNation, targetNation, 0);
  return 1;
}

// ByteSwapShortInPlace (0x004f2970) and ReadByteSwappedShortArrayFromStream (0x004f2a60)
// are shared stream byte-order helpers, not diplomacy code: they live in
// src/game/core/stream_byteswap.cpp.

// The byte-array twin of BuildTurnEvent2ArraySyncPacketDeltaOrFull below: same packet, same
// full-versus-delta decision, but one byte per element, so a delta record costs 3 bytes and
// the payload is tagged deltaKind21 == 1.
// FUNCTION: IMPERIALISM 0x00544840
TurnEvent2SyncPacket* __cdecl
BuildTurnEvent2ByteArraySyncPacketDeltaOrFull(unsigned int byteCount, unsigned char* current,
                                              unsigned char* baseline) {
  bool sendFull = true;
  int differing = 0;
  if (baseline != 0) {
    if (0 < static_cast<int>(byteCount)) {
      unsigned char* cur = current;
      unsigned int remaining = byteCount;
      do {
        if (*cur != cur[baseline - current]) {
          ++differing;
        }
        ++cur;
        --remaining;
      } while (remaining != 0);
    }
    sendFull = true;
    if (static_cast<unsigned int>(differing * 3) < byteCount) {
      sendFull = false;
    }
  }
  if (sendFull) {
    int packetSize = byteCount + 0x24;
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
    memcpy(packet->payload.raw, current, byteCount);
    packet->deltaKind21 = 0;
    return packet;
  }
  int packetSize = (differing + 0xc) * 3;
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
  packet->deltaKind21 = 1;
  TurnEvent2ByteDeltaEntry* out = packet->payload.byteEntries;
  unsigned char* cur = current;
  for (int i = 0; i < static_cast<int>(byteCount); ++i) {
    if (*cur != cur[baseline - current]) {
      out->index = static_cast<unsigned short>(i);
      out->value = *cur;
      ++out;
    }
    ++cur;
  }
  return packet;
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
    memcpy(packet->payload.raw, current, shortCount * 2);
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
  TurnEvent2ShortDeltaEntry* out = packet->payload.shortEntries;
  short* cur = current;
  for (int i = 0; i < static_cast<int>(shortCount); ++i) {
    if (*cur != cur[baseline - current]) {
      out->index = static_cast<unsigned short>(i);
      out->value = *cur;
      ++out;
    }
    ++cur;
  }
  return packet;
}

// The int-array twin: four bytes per element, so a delta record costs 6 bytes and the
// payload is tagged deltaKind21 == 3.
// FUNCTION: IMPERIALISM 0x00544b30
TurnEvent2SyncPacket* __cdecl
BuildTurnEvent2IntArraySyncPacketDeltaOrFull(int intCount, int* current, int* baseline) {
  bool sendFull = true;
  int differing = 0;
  if (baseline != 0) {
    if (0 < intCount) {
      int* cur = baseline;
      int remaining = intCount;
      do {
        if (cur[current - baseline] != *cur) {
          ++differing;
        }
        ++cur;
        --remaining;
      } while (remaining != 0);
    }
    sendFull = true;
    if (static_cast<unsigned int>(differing * 6) < static_cast<unsigned int>(intCount * 4)) {
      sendFull = false;
    }
  }
  if (sendFull) {
    int packetSize = intCount * 4 + 0x24;
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
    memcpy(packet->payload.raw, current, intCount * 4);
    packet->deltaKind21 = 0;
    return packet;
  }
  int packetSize = (differing + 6) * 6;
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
  packet->deltaKind21 = 3;
  TurnEvent2IntDeltaEntry* out = packet->payload.intEntries;
  int* cur = current;
  for (int i = 0; i < intCount; ++i) {
    if (*cur != cur[baseline - current]) {
      out->index = static_cast<unsigned short>(i);
      out->value = *cur;
      ++out;
    }
    ++cur;
  }
  return packet;
}
