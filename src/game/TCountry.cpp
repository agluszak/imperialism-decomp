#include "game/TCountry.h"

#include "game/TMilitaryUnitOrderState.h"
#include "game/TStream.h"
#include "game/TUnitOrderState.h"
#include "game/diplomacy_globals.h"
#include "game/nation_stream_serialization.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

static const unsigned int kAddrClassDescTCountry = 0x00653670;

static void SwapAdjacentBytesInShortArray(short* entries, int pairCount) {
  for (int i = 0; i < pairCount; ++i) {
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&entries[i]);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
  }
}

// FUNCTION: IMPERIALISM 0x004d6730
char TCountry::ReturnFalseNationStateCapabilityFlag98(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d6750
char TCountry::ReturnFalseNationStateCapabilityFlag9C(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d6790
void TCountry::NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

// FUNCTION: IMPERIALISM 0x004d67b0
CRuntimeClass* TCountry::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(kAddrClassDescTCountry);
}

// SYNTHETIC: IMPERIALISM 0x004d6850
// TCountry::`scalar deleting destructor'
TCountry::~TCountry() {}

// FUNCTION: IMPERIALISM 0x004d6ba0
void TCountry::Free(void) {
  if (this->militaryUnitList44 != 0) {
    this->militaryUnitList44->Call58();
  }
  this->militaryUnitList44 = 0;
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->Call38();
    this->ownedRegionList = 0;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004d6bf0
void TCountry::ReadFrom(TStream* stream) {
  int streamState = reinterpret_cast<int>(stream);
  stream->streamSlot70();
  stream->streamSlot70();

  CString* nationNameSource = reinterpret_cast<CString*>(
      reinterpret_cast<char*>(g_pLocalizationTable) + this->nationSlot * 4 + 0x7c);
  this->identitySharedString1 = *nationNameSource;
  stream->ReadBytes(&this->identitySharedString0, 4);

  stream->ReadBytes(&this->nationSlot, 2);
  stream->ReadBytes(&this->encodedNationSlot, 2);
  stream->ReadBytes(this->unitNameOrdinalByType, 0x3c);
  SwapAdjacentBytesInShortArray(this->unitNameOrdinalByType, 0x1e);

  stream->ReadBytes(&this->unitNameCounter84, 2);
  stream->ReadBytes(&this->treasuryValue10, 4);
  stream->ReadBytes(&this->ownerNationSlot, 4);
  stream->ReadBytes(&this->serializedField8c, 4);
  stream->ReadBytes(this->needLevelByNation, 0x2e);
  SwapAdjacentBytesInShortArray(this->needLevelByNation, 0x17);

  if (this->militaryUnitList44->GetCountSlot48() != 0) {
    this->militaryUnitList44->Call54();
  }
  this->militaryUnitList44->Call18(streamState);

  int recruitCount = 0;
  stream->ReadBytes(&recruitCount, 4);
  int recruitIndex = 1;
  if (recruitCount > 0) {
    do {
      void* raw = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x44));
      TMilitaryUnitOrderState* militaryOrder = 0;
      if (raw != 0) {
        militaryOrder = new (raw) TMilitaryUnitOrderState();
        militaryOrder->InitializeRecruitOrderState(0, 0, this->nationSlot);
        militaryOrder->ReadFromStreamSlot18(stream);
      }
      recruitIndex = recruitIndex + 1;
    } while (recruitIndex <= recruitCount);
  }

  if (this->ownedRegionList->GetCountOrReleaseSlot28() != 0) {
    this->ownedRegionList->Call38();
  }
  this->ownedRegionList->VTableSlot20();
  int regionDeserializeCount = 0;
  stream->ReadBytes(&regionDeserializeCount, 4);
  int regionIndex = 1;
  if (regionDeserializeCount > 0) {
    do {
      int entryValue = 0;
      stream->ReadBytes(&entryValue, 4);
      this->ownedRegionList->ResetSlot14(stream);
      regionIndex = regionIndex + 1;
    } while (regionIndex <= regionDeserializeCount);
  }
}

// Serializes the TCountry base sub-object: the identity strings (stream slot 0xac), the
// nation-slot metrics, the per-unit-type name ordinals, the military unit list and the
// owned-region list. The leading TObject::WriteTo is the no-op base-of-base (0x00485f70).
#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x004d6e60
void TCountry::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);

  stream->streamSlotAc(&this->identitySharedString0);
  stream->streamSlotAc(&this->identitySharedString1);

  stream->WriteBytesSlot78(&this->nationSlot, 2);
  stream->WriteBytesSlot78(&this->encodedNationSlot, 2);
  WriteShortArrayElems(stream, this->unitNameOrdinalByType, 0x1e);
  stream->WriteBytesSlot78(&this->unitNameCounter84, 2);
  stream->WriteBytesSlot78(&this->treasuryValue10, 4);
  stream->WriteBytesSlot78(&this->ownerNationSlot, 4);
  stream->WriteBytesSlot78(&this->serializedField8c, 4);
  WriteShortArrayElems(stream, this->needLevelByNation, 0x17);

  WriteTrackedListToStream(stream, this->militaryUnitList44);
  WriteIntListToStream(stream, this->ownedRegionList);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004d7070
void TCountry::ReadCoreStateAndRecreateCivOrdersFromStream(void* stream, int unusedArg) {
  (void)stream;
  (void)unusedArg;
}

// FUNCTION: IMPERIALISM 0x004d70e0
void TCountry::WriteCoreStateAndTrackedOrdersToStream(void* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x004d7b00
char TCountry::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                             int arg4) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7c00
void TCountry::ApplyJoinEmpireMode0GlobalDiplomacyReset(int targetNationSlot) {
  (void)targetNationSlot;
}

// FUNCTION: IMPERIALISM 0x004d7d70
void TCountry::RemoveRegionIdAndRunTrackedObjectCleanup(int regionId) {
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->RemoveEntryAtSlot50(regionId);
  }
}

// FUNCTION: IMPERIALISM 0x004d7da0
void TCountry::AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet(void) {}

// FUNCTION: IMPERIALISM 0x004d7dd0
void TCountry::ApplyDiplomacyTargetTransitionAndClearGrantEntry(int targetNationSlot,
                                                                int policyCode) {
  (void)targetNationSlot;
  (void)policyCode;
}

// FUNCTION: IMPERIALISM 0x004d7e90
void TCountry::DecrementDiplomacyCounterA2ByValue(int delta) {
  (void)delta;
}

// FUNCTION: IMPERIALISM 0x004d7ee0
int TCountry::SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f00
short TCountry::GetDiplomacyCounterA2(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f20
short TCountry::GetDiplomacyExternalStateB6ByTarget(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f40
short TCountry::QueryNationMetricBySlot7C(short metricSlot) {
  (void)metricSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f60
char TCountry::ReturnFalseNationStateCapabilityFlag90(int arg) {
  (void)arg;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f80
void TCountry::NotifyActionSlot94(int sourceNation, int actionCode) {
  (void)sourceNation;
  (void)actionCode;
}

// FUNCTION: IMPERIALISM 0x004d7fa0
void TCountry::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                              int multiplier) {
  (void)resourceIndex;
  (void)delta;
  (void)multiplier;
}

// FUNCTION: IMPERIALISM 0x004d7fc0
bool TCountry::IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot) {
  (void)targetNationSlot;
  return false;
}

// FUNCTION: IMPERIALISM 0x004d7fe0
void TCountry::QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId) {
  (void)proposalCode;
  (void)targetNationId;
}

// FUNCTION: IMPERIALISM 0x004d8920
void TCountry::ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot, int resetLevel) {
  (void)nationSlot;
  (void)resetLevel;
}
